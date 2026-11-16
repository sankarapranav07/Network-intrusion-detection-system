from shlex import quote

from mininet.cli import CLI as MininetCLI
from mininet.log import error
from mininet.term import makeTerm
from mininet.topo import Topo

BLOCK_LOG = "/run/cn-project-ids/blocks.log"


class ProjectCLI(MininetCLI):
    def do_xterm(self, line, term="xterm"):
        """Open host terminals with live IDS notifications on h2 and h3."""
        if term != "xterm" or not line.split():
            return super().do_xterm(line, term=term)

        for name in line.split():
            if name not in self.mn:
                error(f"node '{name}' not in network\n")
                continue
            if name not in {"h2", "h3"}:
                super().do_xterm(name, term=term)
                continue

            # The shell keeps its PID across exec, so tail stops when it exits.
            watch = (
                f'tail -n 0 -F -s 0.1 --pid="$$" -- {quote(BLOCK_LOG)} 2>/dev/null & '
                "printf '%s\\n' '[IDS] Block watcher started. Waiting for confirmed blocks.'; "
                "exec bash -i"
            )
            self.mn.terms.extend(makeTerm(self.mn[name], term=term, cmd=f"bash -c {quote(watch)}"))


CLI = ProjectCLI  # Loaded by mn --custom.


class CNProjectTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

topos = {'mytopo': (lambda: CNProjectTopo())}
