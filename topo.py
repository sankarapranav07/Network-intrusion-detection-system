from mininet.topo import Topo

class CNProjectTopo(Topo):
    def build(self):
        # Create the OpenFlow switch
        s1 = self.addSwitch('s1')
        
        # Create the hosts
        h1 = self.addHost('h1', ip='10.0.0.1') # Server
        h2 = self.addHost('h2', ip='10.0.0.2') # Normal Client
        h3 = self.addHost('h3', ip='10.0.0.3') # Attacker (Madhu)
        
        # Connect hosts to the switch
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

topos = {'mytopo': (lambda: CNProjectTopo())}
