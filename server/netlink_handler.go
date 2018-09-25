package main

import (
	"log"
	"runtime"

	pb "github.com/linkernetworks/network-controller/messages"
	"github.com/linkernetworks/network-controller/utils"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/linkernetworks/network-controller/docker"
	"github.com/linkernetworks/network-controller/nl"
	"golang.org/x/net/context"
)

func (s *server) FindNetworkNamespacePath(ctx context.Context, req *pb.FindNetworkNamespacePathRequest) (*pb.FindNetworkNamespacePathResponse, error) {
	log.Println("--- Start to Find Network Namespace Path---")
	cli, err := docker.New()
	if err != nil {
		return &pb.FindNetworkNamespacePathResponse{
			Path: "",
			ServerResponse: &pb.Response{
				Success: false,
				Reason:  err.Error(),
			},
		}, err
	}

	containers, err := cli.ListContainer()
	if err != nil {
		return &pb.FindNetworkNamespacePathResponse{
			Path: "",
			ServerResponse: &pb.Response{
				Success: false,
				Reason:  err.Error(),
			},
		}, err
	}

	containerID, err := docker.FindK8SPauseContainerID(containers, req.PodName, req.Namespace, req.PodUUID)
	if err != nil {
		return &pb.FindNetworkNamespacePathResponse{
			Path: "",
			ServerResponse: &pb.Response{
				Success: false,
				Reason:  err.Error(),
			},
		}, err
	}
	if containerID == "" {
		return &pb.FindNetworkNamespacePathResponse{
			Path: "",
			ServerResponse: &pb.Response{
				Success: false,
				Reason:  err.Error(),
			},
		}, err
	}

	containerInfo, err := cli.InspectContainer(containerID)
	if err != nil {
		return &pb.FindNetworkNamespacePathResponse{
			Path: "",
			ServerResponse: &pb.Response{
				Success: false,
				Reason:  err.Error(),
			},
		}, err
	}

	return &pb.FindNetworkNamespacePathResponse{
		Path: docker.GetSandboxKey(containerInfo),
		ServerResponse: &pb.Response{
			Success: true,
			Reason:  "",
		},
	}, err
}

func (s *server) ConnectBridge(ctx context.Context, req *pb.ConnectBridgeRequest) (*pb.Response, error) {
	log.Println("--- Start to Connect Bridge ---")
	runtime.LockOSThread()
	netns, err := ns.GetNS(req.Path)
	if err != nil {
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	log.Printf("Get the netns object success: %s", req.Path)

	hostVethName := utils.GenerateVethName(req.PodUUID, req.ContainerVethName)
	log.Printf("Host veth name to container interface name %s=%s", hostVethName, req.ContainerVethName)
	err = netns.Do(func(hostNS ns.NetNS) error {
		if _, _, err := nl.SetupVeth(req.ContainerVethName, hostVethName, 1500, hostNS); err != nil {
			return err
		}
		return nil
	})
	log.Println("Success setup veth")
	if err != nil {
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	log.Printf("Adding port %s to bridge: %s", hostVethName, req.BridgeName)
	if err := s.OVS.AddPort(req.BridgeName, hostVethName); err != nil {
		log.Println("Add port fail:", err, req.BridgeName, hostVethName)
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	log.Println("Add Port Success")
	return &pb.Response{
		Success: true,
		Reason:  "",
	}, nil
}

func (s *server) ConfigureSriovIface(ctx context.Context, req *pb.ConfigureSriovIfaceRequest) (*pb.Response, error) {
	runtime.LockOSThread()
	log.Println("--- Start to configure interface ---")
	netns, err := ns.GetNS(req.Path)
	if err != nil {
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	if err = nl.SriovSetupVF(req.If0, req.ContainerVethName, req.PodUUID, netns); err != nil {
		log.Printf("failed to set up pod SRIOV VF interface %q from the device %q: %v", req.ContainerVethName, req.If0, err)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		result := &current.Result{}
		result.Interfaces = []*current.Interface{{Name: req.ContainerVethName}}

		ipv4, err := types.ParseCIDR(req.CIDR)
		if err != nil {
			return err
		}
		result.IPs = []*current.IPConfig{
			{
				Version:   "4",
				Interface: current.Int(0),
				Address:   *ipv4,
			},
		}

		return ipam.ConfigureIface(req.ContainerVethName, result)
	})
	if err != nil {
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	return &pb.Response{
		Success: true,
		Reason:  "",
	}, nil
}

func (s *server) ConfigureIface(ctx context.Context, req *pb.ConfigureIfaceRequest) (*pb.Response, error) {
	runtime.LockOSThread()
	log.Println("--- Start to configure interface ---")
	netns, err := ns.GetNS(req.Path)
	if err != nil {
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	err = netns.Do(func(_ ns.NetNS) error {
		result := &current.Result{}
		result.Interfaces = []*current.Interface{{Name: req.ContainerVethName}}

		ipv4, err := types.ParseCIDR(req.CIDR)
		if err != nil {
			return err
		}
		result.IPs = []*current.IPConfig{
			{
				Version:   "4",
				Interface: current.Int(0),
				Address:   *ipv4,
			},
		}

		return ipam.ConfigureIface(req.ContainerVethName, result)
	})
	if err != nil {
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	return &pb.Response{
		Success: true,
		Reason:  "",
	}, nil
}

// Will be deprecated in the future
func (s *server) AddRoute(ctx context.Context, req *pb.AddRouteRequest) (*pb.Response, error) {
	runtime.LockOSThread()
	log.Println("--- Start to add route ---")
	netns, err := ns.GetNS(req.Path)
	if err != nil {
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	err = netns.Do(func(_ ns.NetNS) error {
		dst, err := types.ParseCIDR(req.DstCIDR)
		if err != nil {
			return err
		}
		return nl.AddRoute(dst, req.GwIP, req.ContainerVethName)
	})
	if err != nil {
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	return &pb.Response{
		Success: true,
		Reason:  "",
	}, nil
}

func (s *server) AddRoutesViaInterface(ctx context.Context, req *pb.AddRoutesRequest) (*pb.Response, error) {
	runtime.LockOSThread()
	log.Println("--- Start to add route via interface ---")
	netns, err := ns.GetNS(req.Path)
	if err != nil {
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	err = netns.Do(func(_ ns.NetNS) error {
		for _, dstCIDR := range req.DstCIDRs {
			dst, err := types.ParseCIDR(dstCIDR)
			if err != nil {
				return err
			}
			if err := nl.AddRouteViaInterface(dst, req.ContainerVethName); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	return &pb.Response{
		Success: true,
		Reason:  "",
	}, nil
}

func (s *server) AddRoutesViaGateway(ctx context.Context, req *pb.AddRoutesRequest) (*pb.Response, error) {
	runtime.LockOSThread()
	log.Println("--- Start to add route via gateway ---")
	netns, err := ns.GetNS(req.Path)
	if err != nil {
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	err = netns.Do(func(_ ns.NetNS) error {
		// assume client will send same size of slice
		for i := 0; i < len(req.DstCIDRs); i++ {
			dst, err := types.ParseCIDR(req.DstCIDRs[i])
			if err != nil {
				return err
			}
			if err := nl.AddRouteViaGateway(dst, req.GwIPs[i], req.ContainerVethName); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return &pb.Response{
			Success: false,
			Reason:  err.Error(),
		}, err
	}

	return &pb.Response{
		Success: true,
		Reason:  "",
	}, nil
}
