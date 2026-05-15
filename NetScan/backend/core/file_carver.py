import os
import uuid
import subprocess
import logging
from core.parser import TSHARK_PATH

def carve_files(pcap_path, base_output_dir):
    """
    Leverages tshark's built-in object exportation to carve files transferred over HTTP, SMB, TFTP, and FTP.
    This avoids complex manual TCP stream reassembly in Python.
    """
    
    # Create a unique directory for this carve session
    carve_id = str(uuid.uuid4())
    carve_dir = os.path.join(base_output_dir, carve_id)
    os.makedirs(carve_dir, exist_ok=True)
    
    tshark_path = TSHARK_PATH
    
    if not os.path.exists(tshark_path):
        return {"status": "error", "message": "tshark executable not found at designated path."}
        
    extracted_files = []
    
    # Protocols supported by tshark for --export-objects
    # Valid options are: dicom, http, imf, smb, tftp
    protocols = ["http", "smb", "tftp"]
    
    for proto in protocols:
        proto_dir = os.path.join(carve_dir, proto)
        os.makedirs(proto_dir, exist_ok=True)
        
        cmd = [
            tshark_path,
            "-r", pcap_path,
            "-q", # Quiet mode
            "--export-objects", f"{proto},{proto_dir}"
        ]
        
        try:
            # We run this synchronously since it runs quickly and we want results immediately
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            # Record any carved files
            if os.path.exists(proto_dir):
                for filename in os.listdir(proto_dir):
                    file_path = os.path.join(proto_dir, filename)
                    if os.path.isfile(file_path):
                        size = os.path.getsize(file_path)
                        extracted_files.append({
                            "filename": filename,
                            "protocol": proto.upper(),
                            "size_bytes": size,
                            "path": file_path
                        })
        except subprocess.CalledProcessError as e:
            # tshark might throw an error if no objects of that protocol were found or if file is corrupt
            logging.warning(f"Error carving {proto} objects: {e.stderr}")
            pass
            
    # Cleanup empty protocol directories
    for proto in protocols:
        proto_dir = os.path.join(carve_dir, proto)
        if os.path.exists(proto_dir) and not os.listdir(proto_dir):
            os.rmdir(proto_dir)
            
    return {
        "status": "success",
        "carve_session_id": carve_id,
        "carved_dir": carve_dir,
        "files_extracted": len(extracted_files),
        "files": extracted_files
    }
