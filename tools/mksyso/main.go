// mksyso embeds an .ico (and optional manifest) into an amd64 COFF .syso that `go build` links into the Windows exe for the file icon plus visual styles + DPI awareness; pure stdlib. Usage: go run ./tools/mksyso <in.ico> <out.syso> [manifest.xml]
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
)

const (
	machineAMD64 = 0x8664
	relAddr32NB  = 0x0003 // IMAGE_REL_AMD64_ADDR32NB
	rtIcon       = 3
	rtGroupIcon  = 14
	rtManifest   = 24
	langID       = 0x0409
	scnChar      = 0x40000040 // CNT_INITIALIZED_DATA | MEM_READ
	symStatic    = 3
	subdirFlag   = 0x80000000
)

type icoEntry struct {
	width, height, colorCount, reserved byte
	planes, bitCount                    uint16
	bytesInRes, imageOffset             uint32
	data                                []byte
}

type resource struct {
	typ, id, lang uint32
	data          []byte
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: mksyso <in.ico> <out.syso> [manifest.xml]")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	check(err)
	entries := parseICO(raw)

	var res []resource
	for i, e := range entries {
		res = append(res, resource{typ: rtIcon, id: uint32(i + 1), lang: langID, data: e.data})
	}
	res = append(res, resource{typ: rtGroupIcon, id: 1, lang: langID, data: buildGroup(entries)})
	if len(os.Args) >= 4 {
		manifest, err := os.ReadFile(os.Args[3])
		check(err)
		res = append(res, resource{typ: rtManifest, id: 1, lang: langID, data: manifest})
	}

	check(os.WriteFile(os.Args[2], buildSyso(res), 0o644))
	fmt.Printf("wrote %s (%d icons%s)\n", os.Args[2], len(entries),
		map[bool]string{true: " + manifest", false: ""}[len(os.Args) >= 4])
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseICO(b []byte) []icoEntry {
	if len(b) < 6 || binary.LittleEndian.Uint16(b[2:]) != 1 {
		check(fmt.Errorf("not an .ico file"))
	}
	count := int(binary.LittleEndian.Uint16(b[4:]))
	out := make([]icoEntry, count)
	for i := 0; i < count; i++ {
		o := 6 + i*16
		e := icoEntry{
			width: b[o], height: b[o+1], colorCount: b[o+2], reserved: b[o+3],
			planes:      binary.LittleEndian.Uint16(b[o+4:]),
			bitCount:    binary.LittleEndian.Uint16(b[o+6:]),
			bytesInRes:  binary.LittleEndian.Uint32(b[o+8:]),
			imageOffset: binary.LittleEndian.Uint32(b[o+12:]),
		}
		e.data = b[e.imageOffset : e.imageOffset+e.bytesInRes]
		out[i] = e
	}
	return out
}

// buildSyso lays out a 3-level resource tree (type → id → language) with one language per (type,id), plus one relocation per data entry.
func buildSyso(res []resource) []byte {
	sort.Slice(res, func(i, j int) bool {
		if res[i].typ != res[j].typ {
			return res[i].typ < res[j].typ
		}
		return res[i].id < res[j].id
	})
	var types []uint32
	byType := map[uint32][]resource{}
	for _, r := range res {
		if _, ok := byType[r.typ]; !ok {
			types = append(types, r.typ)
		}
		byType[r.typ] = append(byType[r.typ], r)
	}

	const dirHdr, dirEntry, dataEntrySz = 16, 8, 16
	key := func(t, id uint32) [2]uint32 { return [2]uint32{t, id} }

	off := 0
	offRoot := off
	off += dirHdr + len(types)*dirEntry
	offTypeDir := map[uint32]int{}
	for _, t := range types {
		offTypeDir[t] = off
		off += dirHdr + len(byType[t])*dirEntry
	}
	offIDDir := map[[2]uint32]int{}
	for _, t := range types {
		for _, r := range byType[t] {
			offIDDir[key(t, r.id)] = off
			off += dirHdr + dirEntry
		}
	}
	offDataEntry := map[[2]uint32]int{}
	for _, t := range types {
		for _, r := range byType[t] {
			offDataEntry[key(t, r.id)] = off
			off += dataEntrySz
		}
	}
	offBlob := map[[2]uint32]int{}
	for _, t := range types {
		for _, r := range byType[t] {
			offBlob[key(t, r.id)] = off
			off += len(r.data)
		}
	}
	secSize := off

	sec := make([]byte, secSize)
	putU16 := func(o int, v uint16) { binary.LittleEndian.PutUint16(sec[o:], v) }
	putU32 := func(o int, v uint32) { binary.LittleEndian.PutUint32(sec[o:], v) }
	entry := func(base, idx int, id, target uint32) {
		e := base + dirHdr + idx*dirEntry
		putU32(e, id)
		putU32(e+4, target)
	}

	putU16(offRoot+14, uint16(len(types)))
	for i, t := range types {
		entry(offRoot, i, t, uint32(offTypeDir[t])|subdirFlag)
	}
	for _, t := range types {
		putU16(offTypeDir[t]+14, uint16(len(byType[t])))
		for i, r := range byType[t] {
			entry(offTypeDir[t], i, r.id, uint32(offIDDir[key(t, r.id)])|subdirFlag)
		}
	}
	var relocs []int
	for _, t := range types {
		for _, r := range byType[t] {
			d := offIDDir[key(t, r.id)]
			putU16(d+14, 1)
			entry(d, 0, r.lang, uint32(offDataEntry[key(t, r.id)])) // leaf

			de := offDataEntry[key(t, r.id)]
			putU32(de, uint32(offBlob[key(t, r.id)])) // OffsetToData (relocated)
			putU32(de+4, uint32(len(r.data)))         // Size
			relocs = append(relocs, de)

			copy(sec[offBlob[key(t, r.id)]:], r.data)
		}
	}

	relCount := len(relocs)
	relBytes := make([]byte, relCount*10)
	for i, va := range relocs {
		o := i * 10
		binary.LittleEndian.PutUint32(relBytes[o:], uint32(va))
		binary.LittleEndian.PutUint32(relBytes[o+4:], 0) // symbol 0 = section
		binary.LittleEndian.PutUint16(relBytes[o+8:], relAddr32NB)
	}

	sym := make([]byte, 36)
	copy(sym[0:8], ".rsrc")
	binary.LittleEndian.PutUint16(sym[12:], 1) // SectionNumber
	sym[16] = symStatic
	sym[17] = 1 // one aux record
	binary.LittleEndian.PutUint32(sym[18:], uint32(secSize))
	binary.LittleEndian.PutUint16(sym[22:], uint16(relCount))

	ptrRawData := 60
	ptrReloc := ptrRawData + len(sec)
	ptrSym := ptrReloc + len(relBytes)

	buf := &bytes.Buffer{}
	w16 := func(v uint16) { binary.Write(buf, binary.LittleEndian, v) }
	w32 := func(v uint32) { binary.Write(buf, binary.LittleEndian, v) }

	w16(machineAMD64)
	w16(1) // sections
	w32(0) // timestamp
	w32(uint32(ptrSym))
	w32(2) // symbols (record + aux)
	w16(0)
	w16(0)

	name := make([]byte, 8)
	copy(name, ".rsrc")
	buf.Write(name)
	w32(0)
	w32(0)
	w32(uint32(len(sec)))
	w32(uint32(ptrRawData))
	w32(uint32(ptrReloc))
	w32(0)
	w16(uint16(relCount))
	w16(0)
	w32(scnChar)

	buf.Write(sec)
	buf.Write(relBytes)
	buf.Write(sym)
	w32(4) // string table: size only

	return buf.Bytes()
}

func buildGroup(entries []icoEntry) []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(len(entries)))
	for i, e := range entries {
		buf.WriteByte(e.width)
		buf.WriteByte(e.height)
		buf.WriteByte(e.colorCount)
		buf.WriteByte(e.reserved)
		binary.Write(buf, binary.LittleEndian, e.planes)
		binary.Write(buf, binary.LittleEndian, e.bitCount)
		binary.Write(buf, binary.LittleEndian, e.bytesInRes)
		binary.Write(buf, binary.LittleEndian, uint16(i+1))
	}
	return buf.Bytes()
}
