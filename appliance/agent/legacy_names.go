package main

// Names from before the product was renamed to Yougori.
//
// containerd stores every existing container, image and network under these keys and
// cannot rename them. Changing them would orphan the environments, snapshots and
// networks that existing installs already have, so they stay fixed. Users never see
// them; everything else uses the Yougori names. The host's matching image-name prefix
// is in cli/src/legacy_names.rs.
const (
	// containerd namespace that holds environment containers and their images.
	storageNamespace = "opendock"
	// CNI network, and attachment ID prefix, for container internet access.
	internetNetworkName = "opendock-internet"
	// Prefix of the container labels this agent sets.
	productLabelPrefix = "opendock."
	// Container label marking containers this agent manages.
	managedLabel = productLabelPrefix + "managed"
	// Container label naming the image retained for a container.
	retainedImageLabel = productLabelPrefix + "retained-image"
	// Image name prefix for retained container images and snapshots.
	imageNamePrefix = "opendock.local/"
)

// Mount root inside containers created by earlier releases; workloads may not mount over it.
const legacyContainerMountRoot = "/opendock"

// Comment prefix earlier agents put on the /etc/hosts entries they managed. Such an
// entry is removed whenever this agent updates or removes the entry for the same ID.
const legacyHostsMarkerPrefix = "# opendock:"
