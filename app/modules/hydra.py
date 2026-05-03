import subprocess

def run_hydra(target):

    result = subprocess.run(
        [
            "hydra",
            "-l", "root",
            "-P", "/wordlists/rockyou.txt",
            target,
            "ssh"
        ],
        capture_output=True,
        text=True
    )

    return {"output": result.stdout}