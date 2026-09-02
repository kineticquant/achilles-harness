package main

import (
	"fmt"
	"os/exec"
)

func lookup(id string) {
	q := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
	_ = q
	exec.Command("sh", "-c", "echo "+id)
}
