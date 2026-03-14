import logging
import asyncio
import psutil
import socket
import threading
import queue
import subprocess
import os
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Set
from core.parser import dictify_packet
import pyshark

logger = logging.getLogger(__name__)

TSHARK_PATH = os.environ.get("TSHARK_PATH", r"D:\Wireshark\tshark.exe")

router = APIRouter()

# Global state for managing the live sniffer
active_sniffers: Dict[str, Any] = {}
active_dumpers: Dict[str, subprocess.Popen] = {}
connected_clients: Set[WebSocket] = set()

class InterfaceModel(BaseModel):
    name: str
    addresses: List[str]

@router.get("/interfaces", response_model=List[InterfaceModel])
async def get_network_interfaces():
    """Returns a list of all active network interfaces on the host machine."""
    interfaces = []
    stats = psutil.net_if_addrs()
    for name, addrs in stats.items():
        # Depending on OS and Python version, addr.family can be an int or an Enum. 
        # Safely convert to string to check for IPv4
        addresses = [
            addr.address for addr in addrs 
            if addr.family == socket.AF_INET or 'AF_INET' in str(addr.family)
        ]
        
        # We only return interfaces that have an IPv4 address to filter out loopbacks and dead adapters
        # Filter out obvious loopbacks
        if addresses and name != "Loopback Pseudo-Interface 1" and name != "lo":
            interfaces.append(InterfaceModel(name=name, addresses=addresses))
    return interfaces

async def sniffing_worker(interface: str):
    """Background task that runs the PyShark LiveCapture"""
    logger.info(f"Starting LiveCapture on interface: {interface}")
    print(f"[{interface}] Setting up LiveCapture.")
    
    # We store the thread and stop event so we can clean it up later if needed
    active_sniffers[interface] = True
    active_loop = asyncio.get_running_loop()
    
    # Native thread queue to escape all asyncio conflicts
    packet_queue = queue.Queue()
    
    def sniffing_thread_loop():
        # Because pyshark is so finicky with event loops, we create a fresh one
        # exactly for this thread, isolating it completely from FastAPI.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        print(f"[{interface}] Inside native thread.")
        try:
            # We avoid sniff_continuously() because it uses async generators that
            # crash the Windows ProactorEventLoop violently when spawned in threads.
            # Instead, we do manual batch sniffing.
            while active_sniffers.get(interface):
                # Sniff a small batch of packets at a time blocking
                capture = pyshark.LiveCapture(interface=interface, tshark_path=TSHARK_PATH)
                capture.sniff(timeout=1.0)
                
                if not active_sniffers.get(interface):
                    break
                    
                for packet in capture:
                    parsed = dictify_packet(packet)
                    if parsed:
                        packet_queue.put(parsed)
                        
                # Important: cleanly close PyShark to release the tshark process handles
                capture.close()
                
        except Exception as e:
            print(f"[{interface}] PyShark thread crashed:", e)
            logger.error(f"Live sniff failed on {interface}: {e}")
            active_sniffers[interface] = False
            
        finally:
            print(f"[{interface}] Exiting thread.")
            loop.close()

    async def broadcast_worker():
        """Pulls from the native queue and broadcasts to all websockets"""
        print(f"[{interface}] Broadcaster started. Waiting for packets...")
        while active_sniffers.get(interface):
            try:
                # We offload the blocking get to a thread so it doesn't freeze FastAPI
                parsed = await active_loop.run_in_executor(None, packet_queue.get, True, 1.0)
                
                if connected_clients:
                     dead_clients = set()
                     for client in list(connected_clients):
                          try:
                              await client.send_json({"type": "packet", "data": parsed})
                          except Exception as e:
                              print(f"[{interface}] Failed to send to client: {e}")
                              dead_clients.add(client)
                              
                     for dc in dead_clients:
                          connected_clients.discard(dc)
                          
            except queue.Empty:
                continue # Just loop around to check if we are still active
            except Exception as e:
                print(f"Broadcaster queue error: {e}")
                logger.error(f"Broadcaster queue error: {e}")
                break

    # Start the PyShark native thread
    worker = threading.Thread(target=sniffing_thread_loop, daemon=True)
    worker.start()
    
    # Start the asyncio broadcasting loop
    try:
        await broadcast_worker()
    finally:
        logger.info(f"Stopped LiveCapture on {interface}")
        active_sniffers.pop(interface, None)

@router.post("/sniff/start")
async def start_sniffing(interface: str):
    """Starts the background sniffer on the given interface"""
    if interface in active_sniffers:
        return {"status": "already_running", "interface": interface}
        
    # Start a parallel raw tshark process to dump a perfect PCAP file for the user
    # We save to "backend/captures/interface_live.pcap" safely
    os.makedirs("captures", exist_ok=True)
    pcap_path = os.path.join("captures", f"{interface.replace(' ', '_')}_live.pcap")
    if os.path.exists(pcap_path):
        os.remove(pcap_path) # clear old capture
        
    try:
        dumper = subprocess.Popen(
            [TSHARK_PATH, "-i", interface, "-w", pcap_path, "-F", "pcap"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        active_dumpers[interface] = dumper
    except Exception as e:
        logger.error(f"Failed to start PCAP dumper for {interface}: {e}")

    # Start the worker task in the background
    asyncio.create_task(sniffing_worker(interface))
    return {"status": "started", "interface": interface}

@router.post("/sniff/stop")
async def stop_sniffing(interface: str):
    """Stops the background sniffer for the given interface"""
    if interface in active_sniffers:
        # Pyshark lacks a graceful async stop, so we delete it from the tracker 
        # which breaks the loop inside the worker
        active_sniffers[interface] = None 
        
        # Kill the parallel PCAP dumping subprocess
        if interface in active_dumpers:
            try:
                active_dumpers[interface].terminate()
                active_dumpers[interface].wait(timeout=2)
            except Exception as e:
                logger.error(f"Failed to kill dumper for {interface}: {e}")
            active_dumpers.pop(interface, None)
            
        return {"status": "stopped", "interface": interface}
    return {"status": "not_running", "interface": interface}

@router.get("/sniff/download")
async def download_capture(interface: str):
    """Downloads the PCAP file recorded during the live session"""
    pcap_path = os.path.join("captures", f"{interface.replace(' ', '_')}_live.pcap")
    if os.path.exists(pcap_path):
        return FileResponse(
            path=pcap_path, 
            media_type="application/vnd.tcpdump.pcap", 
            filename=f"live_capture_{interface}.pcap"
        )
    return {"error": "No capture file found."}


@router.websocket("/sniff/stream")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint that React connects to. 
    It will receive a live stream of packets as they are captured.
    """
    await websocket.accept()
    connected_clients.add(websocket)
    logger.info(f"Client connected to live stream. Total clients: {len(connected_clients)}")
    
    try:
        while True:
            # We just keep the connection open waiting for client disconnects
            # The background sniffing_worker actually pushes the data into this socket
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
                
    except WebSocketDisconnect:
        logger.info("Client disconnected from live stream")
    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
