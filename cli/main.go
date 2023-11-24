package main

import (
	"os"
	"fmt"
	"github.com/optimisticninja/osin"
)

func main() {
	p := &osin.Argon2Params{
        Memory:      64 * 1024,
        Iterations:  3,
        Parallelism: 2,
        SaltLength:  16,
        KeyLength:   32,
    }

	argon2, err := osin.GenerateArgon2("42069", p)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(argon2)
}
