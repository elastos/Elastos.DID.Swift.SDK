import UIKit

class ViewController: WMPageController {
    let vcs = [UsageViewController()]
    deinit { }
    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
    }
    
    //MARK: pageController delegate
    override func pageController(_ pageController: WMPageController, viewControllerAt index: Int) -> UIViewController {
        return vcs[index]
    }
    override func numbersOfChildControllers(in pageController: WMPageController) -> Int {
        return vcs.count
    }
    
    override func pageController(_ pageController: WMPageController, preferredFrameFor menuView: WMMenuView) -> CGRect {
        return CGRect(x: 0, y: 0, width: UIScreen.main.bounds.size.width, height: 40)
    }
    
    override func pageController(_ pageController: WMPageController, preferredFrameForContentView contentView: WMScrollView) -> CGRect {
        return CGRect(x: 0, y: 80, width: UIScreen.main.bounds.size.width, height: UIScreen.main.bounds.size.height - 80)
    }
}

