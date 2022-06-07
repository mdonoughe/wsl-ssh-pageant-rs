Archived. I've been using [benpye/wsl-ssh-pageant].

# wsl-ssh-pageant-rs

Similar to [benpye/wsl-ssh-pageant] and [NZSmartie/wsl-ssh-pageant], this allows Linux programs running under WSL to access [PuTTY]'s Pageant SSH authentication agent, or some other compatible agent such as [GPG4Win]'s `gpg-agent` (when configured with `enable-putty-support`).

The difference is this one is written in Rust and provides a similar command interface so it can be registered in your `~/.bash_profile` the same as [OpenSSH]'s `ssh-agent`:

    if [ -z "$SSH_AUTH_SOCK" ] ; then
      eval `<path to wsl-ssh-pageant> -s`
    fi

Note: if you do not already have a `~/.bash_profile`, you should include `. ~/.bashrc` in your profile or you will lose some of the default settings, at least on Ubuntu.

`wsl-ssh-pageant-windows.exe` must be placed in the same folder as `wsl-ssh-pageant`, and this folder must be on a `drvfs` mount such as `/mnt/c` so the Windows component can be executed.

[benpye/wsl-ssh-pageant]: https://github.com/benpye/wsl-ssh-pageant
[NZSmartie/wsl-ssh-pageant]: https://github.com/NZSmartie/wsl-ssh-pageant
[PuTTY]: https://www.chiark.greenend.org.uk/~sgtatham/putty/
[GPG4Win]: https://www.gpg4win.org/
[OpenSSH]: https://www.openssh.com/
