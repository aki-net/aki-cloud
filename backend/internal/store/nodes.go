package store

import (
	"time"

	"aki-cloud/backend/internal/models"
)

// UpsertNode inserts or updates a node snapshot.
func (s *Store) UpsertNode(node models.Node) error {
	nodes, err := s.GetNodes()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	node.UpdatedAt = now
	node.ComputeEdgeIPs()
	found := false
	for i, existing := range nodes {
		if existing.ID == node.ID {
			if node.CreatedAt.IsZero() {
				node.CreatedAt = existing.CreatedAt
			}
			nodes[i] = node
			found = true
			break
		}
	}
	if !found {
		if node.CreatedAt.IsZero() {
			node.CreatedAt = now
		}
		nodes = append(nodes, node)
	}
	return s.SaveNodes(nodes)
}

// DeleteNode removes a node by id.
func (s *Store) DeleteNode(id string) error {
	nodes, err := s.GetNodes()
	if err != nil {
		return err
	}
	out := make([]models.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.ID == id {
			continue
		}
		out = append(out, n)
	}
	return s.SaveNodes(out)
}
