// Smallest possible Mach-O exercising the Obj-C 2 / non-fragile ABI.
//
// Built fixtures live alongside this source:
//
//   xcrun -sdk macosx clang -fobjc-arc -framework Foundation \
//     -target arm64-apple-macos11 -O0 -o objc-tiny-arm64 objc-tiny.m
//   xcrun -sdk macosx clang -fobjc-arc -framework Foundation \
//     -target x86_64-apple-macos11 -O0 -o objc-tiny-x86_64 objc-tiny.m
//   lipo -create objc-tiny-arm64 objc-tiny-x86_64 -output objc-tiny-fat
//
// Exercises every __objc_* section the v0.1 Stage 4 walker decodes:
// __objc_classlist, __objc_protolist, __objc_catlist (via the
// NSString category, since clang merges in-image categories into the
// host class), __objc_methlist (small), __objc_methname,
// __objc_classname, __objc_selrefs, __objc_classrefs, __objc_protorefs,
// __objc_imageinfo, __objc_const, __objc_data.
//
// Mirrors the inventory recorded in `SAMPLES.md:131-157`.

#import <Foundation/Foundation.h>

@protocol Spoken
- (void)speak;
@end

@interface Greeter : NSObject {
    NSString *_name;
}
@property (nonatomic, copy) NSString *name;
- (void)greet;
@end

@implementation Greeter
@synthesize name = _name;
- (void)greet {
    NSLog(@"hi from %@", _name ?: @"world");
}
@end

@interface Greeter (Talkative) <Spoken>
@end

@implementation Greeter (Talkative)
- (void)speak {
    [self greet];
}
@end

// Category on a foreign class — linker cannot merge this, so it
// lives in __objc_catlist with a bind to _OBJC_CLASS_$_NSString.
// Forces the walker to resolve a category's `cls` pointer through
// the chained-fixup binds table.
@interface NSString (Darwinscope)
- (NSString *)darwinscope_reversed;
@end

@implementation NSString (Darwinscope)
- (NSString *)darwinscope_reversed {
    NSUInteger n = self.length;
    NSMutableString *out = [NSMutableString stringWithCapacity:n];
    for (NSUInteger i = n; i > 0; i--) {
        [out appendFormat:@"%C", [self characterAtIndex:i - 1]];
    }
    return out;
}
@end

int main(void) {
    @autoreleasepool {
        Greeter *g = [Greeter new];
        g.name = @"darwinscope";
        [g speak];
        NSString *s = [@"hello" darwinscope_reversed];
        NSLog(@"reversed: %@", s);
    }
    return 0;
}
