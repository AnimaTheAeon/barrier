# Barrier changes

Each version's "- " lines become its release notes.

## 1.1.8

- The kill switch is always on and can't be turned off: Lifestream uses Barrier's connection, so nothing may ever leave outside the VPN
- The kill switch is up from the very first moment the container starts, and changes to it swap in all at once, so there's never a gap
- The VPN's own connection port is open only to Barrier itself. Before, any program in Barrier's network could reach any internet address on that port while the VPN was down
- Name lookups outside the tunnel (to your router or Docker) are only for Barrier itself; Lifestream's lookups always go through the VPN
- "Home network ranges" only accept real home ranges (192.168.x, 10.x, 172.16-31.x), and refuse a change that would cut off the device you're using
- If Barrier's container restarts, Lifestream is restarted so it rejoins the network instead of sitting with no connection
- Checked with a new leak test: real Barrier and Lifestream, a real VPN server, and a fake internet that logs every connection, across 11 failure cases. No leaks

## 1.1.7

- Fixes the page: since 1.1.2 a typo in the page's script stopped every button from working (Connect, Check now, Check setup, Test kill switch) and left the version showing a dash
- Every release is now tested by opening the page in a real browser and using each of those buttons

## 1.1.6

- Finishes bringing over your login, locations and settings from the old Container Manager setup if an earlier start stopped half-way, so it connects to your usual location by itself. This happens once; locations you remove later stay removed
- Lifestream reconnects to Barrier by itself within a minute after Barrier is installed or upgraded. No more reinstalling Lifestream
- Package Center shows "Running" exactly when Barrier's page is up
- A settings file that can't be saved no longer stops Barrier from connecting

## 1.1.5

- Package Center shows Barrier as running again. It could say "Run" while Barrier was working fine

## 1.1.4

- Fixes the package version not starting: DSM ran it without the rights it needs to build the VPN tunnel and save its settings, so it restarted over and over. It now runs with them
- Brings over the page password from the old Container Manager setup even if the first try failed

## 1.1.3

- If the VPN says it's connected but nothing gets through it (not even name lookups) for 3 minutes, Barrier reconnects by itself. Before, a dead tunnel could sit "connected" for hours and leave Lifestream stuck on "Getting info"
- The Connection log says when and why it reconnected

## 1.1.2

- A copy that can't install updates by itself now says how to turn updates on, instead of asking for a package install.

## 1.1.1

- Update messages say "update server" and never include a web address
- Package Center no longer shows developer or support links; the developer is shown as Barrier

## 1.1.0

- Barrier is now a Synology package: install the .spk in Package Center. No more copying folders or building in Container Manager
- No Task Scheduler boot task needed: Barrier switches the VPN's tunnel device on by itself
- Updates card: Update now, and install updates automatically (on by default). Only Barrier's app restarts; the container and Lifestream inside it keep running, the kill switch stays on, and it reconnects to the same location
- If a new version won't start, Barrier goes back to the one that came with the package
- Page password moved into Settings, where you can change or remove it
- On first start, brings over the login, locations, settings and page password from the old Container Manager project
