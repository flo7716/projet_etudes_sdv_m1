import subprocess

def run_hydra(target, user="root", passlist="/usr/share/wordlists/rockyou.txt"):

    result = subprocess.run(
        [
            "hydra",
            "-l", user,
            "-P", passlist,
            target,
            "ssh"
        ],
        capture_output=True,
        text=True
    )

    return {"output": result.stdout}
