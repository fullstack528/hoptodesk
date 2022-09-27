import 'package:flutter/material.dart';
import 'package:flutter_hbb/pages/chat_page.dart';
import 'package:flutter_hbb/pages/server_page.dart';
import 'package:flutter_hbb/pages/settings_page.dart';
import '../common.dart';
import '../widgets/overlay.dart';
import 'connection_page.dart';

abstract class PageShape extends Widget {
  final String title = "";
  final Icon icon = Icon(null);
  final List<Widget> appBarActions = [];
}

final homeKey = GlobalKey<_HomePageState>();

class HomePage extends StatefulWidget {
  HomePage({Key? key}) : super(key: key);

  @override
  _HomePageState createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  var _selectedIndex = 0;
  final List<PageShape> _pages = [];

  void refreshPages() {
    setState(() {
      initPages();
    });
  }

  @override
  void initState() {
    super.initState();
    initPages();
  }

  void initPages() {
    _pages.clear();
    _pages.add(ConnectionPage());
    if (isAndroid) {
      _pages.addAll([ChatPage(), ServerPage()]);
    }
    _pages.add(SettingsPage());
  }

  @override
  Widget build(BuildContext context) {
    return WillPopScope(
        onWillPop: () async {
          if (_selectedIndex != 0) {
            setState(() {
              _selectedIndex = 0;
            });
          } else {
            return true;
          }
          return false;
        },
        child: Scaffold(
          backgroundColor: MyTheme.grayBg,
          appBar: AppBar(
            backgroundColor:  MyTheme.headerGray,
            centerTitle: true,
            title: Text("HopToDesk"),
            actions: _pages.elementAt(_selectedIndex).appBarActions,
          ),
          bottomNavigationBar: BottomNavigationBar(
            key: navigationBarKey,
            items: _pages
                .map((page) =>
                    BottomNavigationBarItem(icon: page.icon, label: page.title))
                .toList(),
            currentIndex: _selectedIndex,
            type: BottomNavigationBarType.fixed,
            selectedItemColor: MyTheme.accent,
            unselectedItemColor: MyTheme.darkGray,
            onTap: (index) => setState(() {
              // close chat overlay when go chat page
              if (index == 1 && _selectedIndex != index) {
                hideChatIconOverlay();
                hideChatWindowOverlay();
              }
              _selectedIndex = index;
            }),
          ),
          body: _pages.elementAt(_selectedIndex),
        ));
  }
}

class WebHomePage extends StatelessWidget {
  final connectionPage = ConnectionPage();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: MyTheme.grayBg,
      appBar: AppBar(
        centerTitle: true,
        title: Text("HopToDesk"),
        actions: connectionPage.appBarActions,
      ),
      body: connectionPage,
    );
  }
}
