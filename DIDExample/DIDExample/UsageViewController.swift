import UIKit
import SnapKit

class UsageViewController: UIViewController,UITableViewDelegate,UITableViewDataSource {
    var mainTableView: UITableView!
    var uageMethods: [UsageInfo] = []
    var usageEvents: [String] = []
    
    deinit { }

    override func viewDidLoad() {
        super.viewDidLoad()
        creatTableView()
        configData()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
    }

    func configData() {
        self.navigationController?.navigationBar.isTranslucent = false
        let info = ["Create Presentation", "Initialize DID", "Issue Credential", "Parse JWT", "Presentation In JWT"]
        for item in info {
            let usageInfo = UsageInfo()
            usageInfo.name = item
            uageMethods.append(usageInfo)
        }
    }
    
    func creatTableView() {
        mainTableView = UITableView(frame: CGRect.zero, style: UITableView.Style.grouped)
        mainTableView.delegate = self as UITableViewDelegate
        mainTableView.dataSource = self as UITableViewDataSource
        mainTableView.estimatedRowHeight = 50
        mainTableView.estimatedSectionHeaderHeight = 395;
        mainTableView.estimatedSectionFooterHeight = 0;
        mainTableView.rowHeight = UITableView.automaticDimension
        mainTableView.rowHeight = 56
        mainTableView.separatorStyle = .none
        mainTableView.register(UsageListCell.self, forCellReuseIdentifier: "UsageListCell")
        self.view.addSubview(mainTableView)
        mainTableView.snp.makeConstraints { (make) in
            make.top.left.right.equalToSuperview()

            if #available(iOS 11.0, *) {
                make.bottom.equalTo(view.safeAreaLayoutGuide)
            } else {
                // Fallback on earlier versions
                make.bottom.equalToSuperview().offset(-49)
            }
        }
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return uageMethods.count
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {

        let cell:UsageListCell = tableView.dequeueReusableCell(withIdentifier: "UsageListCell") as! UsageListCell
        cell.model = uageMethods[indexPath.row]
        return cell
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        switch indexPath.row {
        case 0:
            _ = CreatePresentation()
        case 1:
            _ = InitializeDID()
        case 2:
            _ = IssueCredential()
        case 3:
            _ = ParseJWT()
        case 4:
            _ = PresentationInJWT()
        default: break
        }
    }

}
