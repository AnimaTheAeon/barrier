# Barrier changes

Each version's "- " lines become its release notes.

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
