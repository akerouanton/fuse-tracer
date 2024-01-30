package kallsyms

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
)

type Kallsyms []Ksym

func (k Kallsyms) Len() int {
	return len(k)
}

func (k Kallsyms) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}

func (k Kallsyms) Less(i, j int) bool {
	return k[i].Addr < k[i].Addr
}

var kallsyms Kallsyms

type Ksym struct {
	Addr uint64
	Typ  string
	Name string
}

func LoadKallsyms(filepath string) error {
	f, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	kallsyms = make([]Ksym, 0)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var ksym Ksym
		var addr string
		if _, err := fmt.Sscanf(scanner.Text(), "%s %s %s", &addr, &ksym.Typ, &ksym.Name); err != nil {
			panic(err)
		}

		ksym.Addr, err = strconv.ParseUint(addr, 16, 64)
		if err != nil {
			panic(err)
		}

		kallsyms = append(kallsyms, ksym)
	}

	slices.SortFunc(kallsyms, func(a, b Ksym) int {
		return cmp.Compare(a.Addr, b.Addr)
	})
	// fmt.Printf("%#v", kallsyms)

	return nil
}

func SearchKsym(addr uint64) (string, error) {
	if len(kallsyms) == 0 {
		return "", errors.New("kallsyms has not been loaded")
	}

	start := 0
	end := len(kallsyms)

	for start < end {
		mid := start + (end-start)/2
		result := int64(addr) - int64(kallsyms[mid].Addr)

		if result < 0 {
			end = mid
		} else if result > 0 {
			start = mid + 1
		} else {
			return kallsyms[mid].Name, nil
		}
	}

	if start >= 1 && kallsyms[start-1].Addr < addr {
		if (len(kallsyms) > start && addr < kallsyms[start].Addr) || len(kallsyms) == start {
			return kallsyms[start-1].Name, nil
		}
	}

	return "[unknown]", os.ErrNotExist
}
