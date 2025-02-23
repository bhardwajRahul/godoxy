package docker

import (
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/yusing/go-proxy/internal/utils/strutils"
)

type (
	containerHelper struct {
		*container.Summary
		image *ContainerImage
	}
	ContainerImage struct {
		Author string
		Name   string
		Tag    string
	}
)

// getDeleteLabel gets the value of a label and then deletes it from the container.
// If the label does not exist, an empty string is returned.
func (c containerHelper) getDeleteLabel(label string) string {
	if l, ok := c.Labels[label]; ok {
		delete(c.Labels, label)
		return l
	}
	return ""
}

func (c containerHelper) getAliases() []string {
	if l := c.getDeleteLabel(LabelAliases); l != "" {
		return strutils.CommaSeperatedList(l)
	}
	return []string{c.getName()}
}

func (c containerHelper) getName() string {
	return strings.TrimPrefix(c.Names[0], "/")
}

func (c containerHelper) parseImage() *ContainerImage {
	colonSep := strutils.SplitRune(c.Image, ':')
	slashSep := strutils.SplitRune(colonSep[0], '/')
	im := new(ContainerImage)
	if len(slashSep) > 1 {
		im.Author = slashSep[len(slashSep)-1]
		im.Name = strings.Join(slashSep[:len(slashSep)-1], "/")
	} else {
		im.Author = "library"
		im.Name = colonSep[0]
	}
	if len(colonSep) > 1 {
		im.Tag = colonSep[1]
	}
	return im
}

func (c containerHelper) getPublicPortMapping() PortMapping {
	res := make(PortMapping)
	for _, v := range c.Ports {
		if v.PublicPort == 0 {
			continue
		}
		res[int(v.PublicPort)] = v
	}
	return res
}

func (c containerHelper) getPrivatePortMapping() PortMapping {
	res := make(PortMapping)
	for _, v := range c.Ports {
		res[int(v.PrivatePort)] = v
	}
	return res
}

func (c containerHelper) IsBlacklisted() bool {
	if c.image == nil {
		c.image = c.parseImage()
	}
	return c.image.IsBlacklisted()
}
