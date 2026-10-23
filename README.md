# Argonite behaviour tests

When a moderator on [Argonite](https://argonite.org) asks for it, a mod, plugin or modpack is run
inside real Minecraft on fresh GitHub-hosted Linux, Windows and macOS machines:

- the server is installed with the file's loader, the file and its required dependencies are added,
  and a game client joins the server;
- the network is cut off, and every attempt to reach the internet is recorded;
- believable bait files (browser, Discord, SSH, wallet and launcher data) are planted, each with a
  unique marker, and any access to them is recorded;
- afterwards the machine is checked for changed jars, new programs and anything set to run later.

Each run starts on a new virtual machine and is thrown away afterwards. The machines hold no secrets:
they prove who they are to Argonite with GitHub's own short-lived workflow identity, and each report
is tied to the one test run that claimed it.

The workflows only run when Argonite starts them.
