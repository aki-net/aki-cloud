package store

import (
	"time"

	"aki-cloud/backend/internal/models"
)

// UpsertNode inserts or updates a node snapshot.
func (s *Store) UpsertNode(node models.Node) error {
	nodes, err := s.GetNodesIncludingDeleted()
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

// MarkNodeDeleted records a tombstone for the given node.
func (s *Store) MarkNodeDeleted(id string, nodeID string, at time.Time) error {
	nodes, err := s.GetNodesIncludingDeleted()
	if err != nil {
		return err
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	found := false
	for i := range nodes {
		if nodes[i].ID != id {
			continue
		}
		nodes[i].MarkDeleted(at)
		if nodes[i].CreatedAt.IsZero() {
			nodes[i].CreatedAt = at
		}
		nodes[i].Version.Counter++
		if nodes[i].Version.Counter <= 0 {
			nodes[i].Version.Counter = 1
		}
		nodes[i].Version.NodeID = nodeID
		nodes[i].Version.Updated = at.Unix()
		nodes[i].UpdatedAt = at
		found = true
		break
	}
	if !found {
		node := models.Node{
			ID:        id,
			CreatedAt: at,
			UpdatedAt: at,
			Version: models.ClockVersion{
				Counter: 1,
				NodeID:  nodeID,
				Updated: at.Unix(),
			},
		}
		node.MarkDeleted(at)
		nodes = append(nodes, node)
	}
	return s.SaveNodes(nodes)
}
