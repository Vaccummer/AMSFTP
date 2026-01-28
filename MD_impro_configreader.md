@./tomlread

@include\AMConfigManager.hpp

@config\config.toml

@config\settings.toml

@tomlread\src\lib.rs

我现在需要改用rust的库来读取和写入toml文件, rs文件目录已给出, 目前还存在编译报错

I want use rust lib to read and write toml file, rs src dir is given above, but there's still compile error, correct it

error[E0382]: use of moved value: `item`
   --> src\lib.rs:460:17
    |
407 | fn apply_json_updates_append_new(item: &mut Item, j: &J) {
    |                                  ---- move occurs because `item` has type `&mut Item`, which does not implement the `Copy` trait
408 |     match (item, j) {
    |            ---- value moved here
...
460 |                 *item = new_item;
    |                 ^^^^^ value used here after move

I have nlohmann-json for json-parse

expose rust functions to C++, and use these functions to improve 

configprocessor in @include\base\AMCommonTools.hpp

produce a format json shcuema file
