package util

import "fmt"

func PrintMap(m map[string]interface{}) {
	for k, v := range m {
		fmt.Printf("%s: %v\n", k, v)
	}
}
