# -*- mode: ruby -*-
# WireGuard ZK Handshake — two-VM demo
#
# PRE-REQUISITE (once per machine):
#   1. Build binaries on host:
#        cd wireguard-6.8 && make -C /lib/modules/6.8.0-59-generic/build M=$(pwd) modules
#        cd userspace/wg-zk-daemon && cargo build --release
#        cd userspace/gen-pk && cargo build --release
#   2. Build the base box (installs kernel 6.8.0-59-generic):
#        cd vagrant && bash build-base.sh
#
# USAGE:
#   vagrant up          # generates keys, spins up gateway + client, runs ping test
#   vagrant destroy -f  # tear everything down
#
# Network layout:
#   gateway  eth1=192.168.100.1  wg1r=192.168.1.2  dum0r=10.20.10.10/24
#   client   eth1=192.168.100.2  wg1l=192.168.1.1  dum0l=10.10.10.10/24

GATEWAY_IP = "192.168.100.1"
CLIENT_IP  = "192.168.100.2"
BASE_BOX   = "wgzk-base"

Vagrant.configure("2") do |config|
  config.vm.box = BASE_BOX
  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 512
    vb.cpus   = 1
    vb.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
  end

  # Generate all keys on HOST before any VM boots
  config.trigger.before :up do |t|
    t.name = "Generate WireGuard + ZK keys"
    t.run  = { path: "vagrant/keygen.sh" }
  end

  # Both VMs: load wireguard.ko from host
  config.vm.provision "shell", path: "vagrant/02-load-module.sh"

  # ── GATEWAY ─────────────────────────────────────────────────────────────────
  config.vm.define "gateway", primary: true do |gw|
    gw.vm.hostname = "wgzk-gateway"
    gw.vm.network "private_network", ip: GATEWAY_IP,
                  virtualbox__intnet: "wgzk-internal"
    gw.vm.provision "shell", path: "vagrant/03-gateway.sh",
                    env: { "PEER_IP" => CLIENT_IP }
  end

  # ── CLIENT ───────────────────────────────────────────────────────────────────
  config.vm.define "client" do |cl|
    cl.vm.hostname = "wgzk-client"
    cl.vm.network "private_network", ip: CLIENT_IP,
                  virtualbox__intnet: "wgzk-internal"
    cl.vm.provision "shell", path: "vagrant/03-client.sh",
                    env: { "PEER_IP" => GATEWAY_IP }
    cl.vm.provision "shell", path: "vagrant/04-test.sh"
  end
end
