// Source for the `swift-tiny` Tier-1 synthesized fixture.
//
// Exercises every Swift 5 metadata section the Stage 5 walker
// covers — see `SAMPLES.md:159-184` and `ToDo.md` Stage 5.
//
// One protocol, one struct conforming to it, one class with a
// stored mutable property and a method (vtable entry source), one
// enum with a payload and an empty case, plus a closure that
// captures a class instance (capture descriptor source).
//
// Build:
//   swiftc -O -target arm64-apple-macos13.0  -o swift-tiny-arm64  swift-tiny.swift
//   swiftc -O -target x86_64-apple-macos13.0 -o swift-tiny-x86_64 swift-tiny.swift
//   lipo -create -output swift-tiny-fat swift-tiny-arm64 swift-tiny-x86_64

protocol Greeter { func greet() }

struct Hello: Greeter {
    let name: String
    func greet() { print("hi, \(name)") }
}

class Counter {
    var count: Int = 0
    func bump(_ k: Int = 1) { count += k }
}

enum Mood { case happy, sad(String) }

let h = Hello(name: "world")
h.greet()
let c = Counter()
let bumper = { [c] in c.bump() }
bumper()
print(Mood.sad("rain"))
