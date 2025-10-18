package backup

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	mega "github.com/t3rm1n4l/go-mega"
)

type megaLoginFunc func(username, password string) (*mega.Mega, func(), error)

func loginToMega(username, password string) (*mega.Mega, func(), error) {
	client := mega.New()
	client.SetTimeOut(45 * time.Second)
	client.SetUploadWorkers(4)
	client.SetDownloadWorkers(4)
	if err := client.Login(username, password); err != nil {
		return nil, nil, err
	}
	cleanup := func() {}
	return client, cleanup, nil
}

func (s *Service) login(ctx context.Context, settings nodeSettings) (*mega.Mega, func(), error) {
	client, cleanup, err := s.loginFn(settings.Username, settings.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("mega login failed: %w", err)
	}
	return client, cleanup, nil
}

func ensurePath(m *mega.Mega, parts []string) (*mega.Node, error) {
	node := m.FS.GetRoot()
	if node == nil {
		return nil, errors.New("mega: root not available")
	}
	for _, part := range parts {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		child, err := findChild(m, node, part)
		if err != nil {
			return nil, err
		}
		if child == nil {
			child, err = m.CreateDir(part, node)
			if err != nil {
				return nil, err
			}
		}
		node = child
	}
	return node, nil
}

func findChild(m *mega.Mega, parent *mega.Node, name string) (*mega.Node, error) {
	children, err := m.FS.GetChildren(parent)
	if err != nil {
		return nil, err
	}
	for _, child := range children {
		if strings.EqualFold(child.GetName(), name) {
			return child, nil
		}
	}
	return nil, nil
}

func collectFiles(m *mega.Mega, parent *mega.Node) ([]*mega.Node, error) {
	children, err := m.FS.GetChildren(parent)
	if err != nil {
		return nil, err
	}
	files := make([]*mega.Node, 0, len(children))
	for _, child := range children {
		if child.GetType() == mega.FILE {
			files = append(files, child)
		}
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].GetTimeStamp().After(files[j].GetTimeStamp())
	})
	return files, nil
}
