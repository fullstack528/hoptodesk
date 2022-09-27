import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/models/file_model.dart';
import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:provider/provider.dart';
import 'package:flutter_breadcrumb/flutter_breadcrumb.dart';
import 'package:wakelock/wakelock.dart';
import 'package:toggle_switch/toggle_switch.dart';

import '../common.dart';
import '../models/model.dart';
import '../widgets/dialog.dart';

class FileManagerPage extends StatefulWidget {
  FileManagerPage({Key? key, required this.id}) : super(key: key);
  final String id;

  @override
  State<StatefulWidget> createState() => _FileManagerPageState();
}

class _FileManagerPageState extends State<FileManagerPage> {
  final model = FFI.fileModel;
  final _selectedItems = SelectedItems();
  final _breadCrumbScroller = ScrollController();

  @override
  void initState() {
    super.initState();
    FFI.connect(widget.id, isFileTransfer: true);
    showLoading(translate('Connecting...'));
    FFI.ffiModel.updateEventListener(widget.id);
    Wakelock.enable();
  }

  @override
  void dispose() {
    model.onClose();
    FFI.close();
    SmartDialog.dismiss();
    Wakelock.disable();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => ChangeNotifierProvider.value(
      value: FFI.fileModel,
      child: Consumer<FileModel>(builder: (_context, _model, _child) {
        return WillPopScope(
            onWillPop: () async {
              if (model.selectMode) {
                model.toggleSelectMode();
              } else {
                goBack();
              }
              return false;
            },
            child: Scaffold(
              backgroundColor: MyTheme.grayBg,
              appBar: AppBar(
                leading: Row(children: [
                  IconButton(icon: Icon(Icons.close), onPressed: clientClose),
                ]),
                centerTitle: true,
                title: ToggleSwitch(
                  initialLabelIndex: model.isLocal ? 0 : 1,
                  activeBgColor: [MyTheme.idColor],
                  inactiveBgColor: MyTheme.grayBg,
                  inactiveFgColor: Colors.black54,
                  totalSwitches: 2,
                  minWidth: 100,
                  fontSize: 15,
                  iconSize: 18,
                  labels: [translate("Local"), translate("Remote")],
                  icons: [Icons.phone_android_sharp, Icons.screen_share],
                  onToggle: (index) {
                    final current = model.isLocal ? 0 : 1;
                    if (index != current) {
                      model.togglePage();
                    }
                  },
                ),
                actions: [
                  PopupMenuButton<String>(
                      icon: Icon(Icons.more_vert),
                      itemBuilder: (context) {
                        return [
                          PopupMenuItem(
                            child: Row(
                              children: [
                                Icon(Icons.refresh, color: Colors.black),
                                SizedBox(width: 5),
                                Text(translate("Refresh File"))
                              ],
                            ),
                            value: "refresh",
                          ),
                          PopupMenuItem(
                            child: Row(
                              children: [
                                Icon(Icons.check, color: Colors.black),
                                SizedBox(width: 5),
                                Text(translate("Multi Select"))
                              ],
                            ),
                            value: "select",
                          ),
                          PopupMenuItem(
                            child: Row(
                              children: [
                                Icon(Icons.folder_outlined,
                                    color: Colors.black),
                                SizedBox(width: 5),
                                Text(translate("Create Folder"))
                              ],
                            ),
                            value: "folder",
                          ),
                          PopupMenuItem(
                            child: Row(
                              children: [
                                Icon(
                                    model.currentShowHidden
                                        ? Icons.check_box_outlined
                                        : Icons.check_box_outline_blank,
                                    color: Colors.black),
                                SizedBox(width: 5),
                                Text(translate("Show Hidden Files"))
                              ],
                            ),
                            value: "hidden",
                          )
                        ];
                      },
                      onSelected: (v) {
                        if (v == "refresh") {
                          model.refresh();
                        } else if (v == "select") {
                          _selectedItems.clear();
                          model.toggleSelectMode();
                        } else if (v == "folder") {
                          final name = TextEditingController();
                          DialogManager.show(
                              (setState, close) => CustomAlertDialog(
                                      title: Text(translate("Create Folder")),
                                      content: Column(
                                        mainAxisSize: MainAxisSize.min,
                                        children: [
                                          TextFormField(
                                            decoration: InputDecoration(
                                              labelText: translate(
                                                  "Please enter the folder name"),
                                            ),
                                            controller: name,
                                          ),
                                        ],
                                      ),
                                      actions: [
                                        TextButton(
                                            style: flatButtonStyle,
                                            onPressed: () => close(false),
                                            child: Text(translate("Cancel"))),
                                        ElevatedButton(
                                            style: flatButtonStyle,
                                            onPressed: () {
                                              if (name.value.text.isNotEmpty) {
                                                model.createDir(PathUtil.join(
                                                    model.currentDir.path,
                                                    name.value.text,
                                                    model.currentIsWindows));
                                                close();
                                              }
                                            },
                                            child: Text(translate("OK")))
                                      ]));
                        } else if (v == "hidden") {
                          model.toggleShowHidden();
                        }
                      }),
                ],
              ),
              body: body(),
              bottomSheet: bottomSheet(),
            ));
      }));

  bool needShowCheckBox() {
    if (!model.selectMode) {
      return false;
    }
    return !_selectedItems.isOtherPage(model.isLocal);
  }

  Widget body() {
    final isLocal = model.isLocal;
    final fd = model.currentDir;
    final entries = fd.entries;
    return Column(children: [
      headTools(),
      Expanded(
          child: ListView.builder(
        itemCount: entries.length + 1,
        itemBuilder: (context, index) {
          if (index >= entries.length) {
            return listTail();
          }
          var selected = false;
          if (model.selectMode) {
            selected = _selectedItems.contains(entries[index]);
          }

          final sizeStr = entries[index].isFile
              ? readableFileSize(entries[index].size.toDouble())
              : "";
          return Card(
            child: ListTile(
              leading: Icon(
                  entries[index].isFile ? Icons.feed_outlined : Icons.folder,
                  size: 40),
              title: Text(entries[index].name),
              selected: selected,
              subtitle: Text(
                entries[index]
                        .lastModified()
                        .toString()
                        .replaceAll(".000", "") +
                    "   " +
                    sizeStr,
                style: TextStyle(fontSize: 12, color: MyTheme.darkGray),
              ),
              trailing: needShowCheckBox()
                  ? Checkbox(
                      value: selected,
                      onChanged: (v) {
                        if (v == null) return;
                        if (v && !selected) {
                          _selectedItems.add(isLocal, entries[index]);
                        } else if (!v && selected) {
                          _selectedItems.remove(entries[index]);
                        }
                        setState(() {});
                      })
                  : PopupMenuButton<String>(
                      icon: Icon(Icons.more_vert),
                      itemBuilder: (context) {
                        return [
                          PopupMenuItem(
                            child: Text(translate("Delete")),
                            value: "delete",
                          ),
                          PopupMenuItem(
                            child: Text(translate("Multi Select")),
                            value: "multi_select",
                          ),
                          PopupMenuItem(
                            child: Text(translate("Properties")),
                            value: "properties",
                            enabled: false,
                          )
                        ];
                      },
                      onSelected: (v) {
                        if (v == "delete") {
                          final items = SelectedItems();
                          items.add(isLocal, entries[index]);
                          model.removeAction(items);
                        } else if (v == "multi_select") {
                          _selectedItems.clear();
                          model.toggleSelectMode();
                        }
                      }),
              onTap: () {
                if (model.selectMode && !_selectedItems.isOtherPage(isLocal)) {
                  if (selected) {
                    _selectedItems.remove(entries[index]);
                  } else {
                    _selectedItems.add(isLocal, entries[index]);
                  }
                  setState(() {});
                  return;
                }
                if (entries[index].isDirectory) {
                  model.openDirectory(entries[index].path);
                  breadCrumbScrollToEnd();
                } else {
                  // Perform file-related tasks.
                }
              },
              onLongPress: () {
                _selectedItems.clear();
                model.toggleSelectMode();
                if (model.selectMode) {
                  _selectedItems.add(isLocal, entries[index]);
                }
                setState(() {});
              },
            ),
          );
        },
      ))
    ]);
  }

  goBack() {
    model.goToParentDirectory();
  }

  breadCrumbScrollToEnd() {
    Future.delayed(Duration(milliseconds: 200), () {
      _breadCrumbScroller.animateTo(
          _breadCrumbScroller.position.maxScrollExtent,
          duration: Duration(milliseconds: 200),
          curve: Curves.fastLinearToSlowEaseIn);
    });
  }

  Widget headTools() => Container(
          child: Row(
        children: [
          Expanded(
              child: BreadCrumb(
            items: getPathBreadCrumbItems(() => model.goHome(), (list) {
              var path = "";
              if (model.currentHome.startsWith(list[0])) {
                // absolute path
                for (var item in list) {
                  path = PathUtil.join(path, item, model.currentIsWindows);
                }
              } else {
                path += model.currentHome;
                for (var item in list) {
                  path = PathUtil.join(path, item, model.currentIsWindows);
                }
              }
              model.openDirectory(path);
            }),
            divider: Icon(Icons.chevron_right),
            overflow: ScrollableOverflow(controller: _breadCrumbScroller),
          )),
          Row(
            children: [
              IconButton(
                icon: Icon(Icons.arrow_upward),
                onPressed: goBack,
              ),
              PopupMenuButton<SortBy>(
                  icon: Icon(Icons.sort),
                  itemBuilder: (context) {
                    return SortBy.values
                        .map((e) => PopupMenuItem(
                              child:
                                  Text(translate(e.toString().split(".").last)),
                              value: e,
                            ))
                        .toList();
                  },
                  onSelected: model.changeSortStyle),
            ],
          )
        ],
      ));

  Widget listTail() {
    return Container(
      height: 100,
      child: Column(
        children: [
          Padding(
            padding: EdgeInsets.fromLTRB(30, 5, 30, 0),
            child: Text(
              model.currentDir.path,
              style: TextStyle(color: MyTheme.darkGray),
            ),
          ),
          Padding(
            padding: EdgeInsets.all(2),
            child: Text(
              "${translate("Total")}: ${model.currentDir.entries.length} ${translate("items")}",
              style: TextStyle(color: MyTheme.darkGray),
            ),
          )
        ],
      ),
    );
  }

  Widget? bottomSheet() {
    final state = model.jobState;
    final isOtherPage = _selectedItems.isOtherPage(model.isLocal);
    final selectedItemsLen = "${_selectedItems.length} ${translate("items")}";
    final local = _selectedItems.isLocal == null
        ? ""
        : " [${_selectedItems.isLocal! ? translate("Local") : translate("Remote")}]";

    if (model.selectMode) {
      if (_selectedItems.length == 0 || !isOtherPage) {
        return BottomSheetBody(
            leading: Icon(Icons.check),
            title: translate("Selected"),
            text: selectedItemsLen + local,
            onCanceled: () => model.toggleSelectMode(),
            actions: [
              IconButton(
                icon: Icon(Icons.compare_arrows),
                onPressed: model.togglePage,
              ),
              IconButton(
                icon: Icon(Icons.delete_forever),
                onPressed: () {
                  if (_selectedItems.length > 0) {
                    model.removeAction(_selectedItems);
                  }
                },
              )
            ]);
      } else {
        return BottomSheetBody(
            leading: Icon(Icons.input),
            title: translate("Paste here?"),
            text: selectedItemsLen + local,
            onCanceled: () => model.toggleSelectMode(),
            actions: [
              IconButton(
                icon: Icon(Icons.compare_arrows),
                onPressed: model.togglePage,
              ),
              IconButton(
                icon: Icon(Icons.paste),
                onPressed: () {
                  model.toggleSelectMode();
                  model.sendFiles(_selectedItems);
                },
              )
            ]);
      }
    }

    switch (state) {
      case JobState.inProgress:
        return BottomSheetBody(
          leading: CircularProgressIndicator(),
          title: translate("Waiting"),
          text:
              "${translate("Speed")}:  ${readableFileSize(model.jobProgress.speed)}/s",
          onCanceled: () => model.cancelJob(model.jobProgress.id),
        );
      case JobState.done:
        return BottomSheetBody(
          leading: Icon(Icons.check),
          title: "${translate("Successful")}!",
          text: "",
          onCanceled: () => model.jobReset(),
        );
      case JobState.error:
        return BottomSheetBody(
          leading: Icon(Icons.error),
          title: "${translate("Error")}!",
          text: "",
          onCanceled: () => model.jobReset(),
        );
      case JobState.none:
        break;
    }
    return null;
  }

  List<BreadCrumbItem> getPathBreadCrumbItems(
      void Function() onHome, void Function(List<String>) onPressed) {
    final path = model.currentShortPath;
    final list = PathUtil.split(path, model.currentIsWindows);
    final breadCrumbList = [
      BreadCrumbItem(
          content: IconButton(
        icon: Icon(Icons.home_filled),
        onPressed: onHome,
      ))
    ];
    breadCrumbList.addAll(list.asMap().entries.map((e) => BreadCrumbItem(
        content: TextButton(
            child: Text(e.value),
            style:
                ButtonStyle(minimumSize: MaterialStateProperty.all(Size(0, 0))),
            onPressed: () => onPressed(list.sublist(0, e.key + 1))))));
    return breadCrumbList;
  }
}

class BottomSheetBody extends StatelessWidget {
  BottomSheetBody(
      {required this.leading,
      required this.title,
      required this.text,
      this.onCanceled,
      this.actions});

  final Widget leading;
  final String title;
  final String text;
  final VoidCallback? onCanceled;
  final List<IconButton>? actions;

  @override
  BottomSheet build(BuildContext context) {
    final _actions = actions ?? [];
    return BottomSheet(
      builder: (BuildContext context) {
        return Container(
            height: 65,
            alignment: Alignment.centerLeft,
            decoration: BoxDecoration(
                color: MyTheme.accent50,
                borderRadius: BorderRadius.vertical(top: Radius.circular(10))),
            child: Padding(
              padding: EdgeInsets.symmetric(horizontal: 15),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Row(
                    children: [
                      leading,
                      SizedBox(width: 16),
                      Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(title, style: TextStyle(fontSize: 18)),
                          Text(text,
                              style: TextStyle(
                                  fontSize: 14, color: MyTheme.grayBg))
                        ],
                      )
                    ],
                  ),
                  Row(children: () {
                    _actions.add(IconButton(
                      icon: Icon(Icons.cancel_outlined),
                      onPressed: onCanceled,
                    ));
                    return _actions;
                  }())
                ],
              ),
            ));
      },
      onClosing: () {},
      backgroundColor: MyTheme.grayBg,
      enableDrag: false,
    );
  }
}

class SelectedItems {
  bool? _isLocal;
  final List<Entry> _items = [];

  List<Entry> get items => _items;

  int get length => _items.length;

  bool? get isLocal => _isLocal;

  add(bool isLocal, Entry e) {
    if (_isLocal == null) {
      _isLocal = isLocal;
    }
    if (_isLocal != null && _isLocal != isLocal) {
      return;
    }
    if (!_items.contains(e)) {
      _items.add(e);
    }
  }

  bool contains(Entry e) {
    return _items.contains(e);
  }

  remove(Entry e) {
    _items.remove(e);
    if (_items.length == 0) {
      _isLocal = null;
    }
  }

  bool isOtherPage(bool currentIsLocal) {
    if (_isLocal == null) {
      return false;
    } else {
      return _isLocal != currentIsLocal;
    }
  }

  clear() {
    _items.clear();
    _isLocal = null;
  }
}
