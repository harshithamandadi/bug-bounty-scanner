import subprocess
import os

def run_sublist3r(domain):
    output_file = "subdomains.txt"
    command = ["python3", "sublist3r.py", "-d", domain, "-o", output_file]
    try:
        subprocess.run(command, check=True)
        with open(output_file, "r") as f:
            subdomains = f.read().splitlines()
        os.remove(output_file)  # clean up
        return subdomains
    except subprocess.CalledProcessError as e:
        return {"error": str(e)}
