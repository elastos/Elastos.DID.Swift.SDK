import UIKit

class UsageListCell: UITableViewCell {
    var usageNameLable: UILabel?
    var model: UsageInfo?{
        didSet{
            usageNameLable?.text = model!.name!
        }
    }
    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        self.selectionStyle = .none
        creatUI()
    }

    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func creatUI() -> Void {
        usageNameLable = UILabel()
        usageNameLable?.backgroundColor = UIColor.clear
        usageNameLable?.text = ""
        usageNameLable?.textAlignment = .center
        usageNameLable!.sizeToFit()
        self.contentView.addSubview(usageNameLable!)
        
        let line = UIView()
        line.backgroundColor = UIColor.lightGray
        self.contentView.addSubview(line)

        usageNameLable?.snp.makeConstraints({ (make) in
            make.top.equalToSuperview()
            make.height.equalTo(54)
            make.left.equalToSuperview().offset(45)
            make.right.equalToSuperview().offset(-45)
            make.bottom.equalToSuperview()
        })

        line.snp.makeConstraints { (make) in
            make.bottom.equalToSuperview()
            make.height.equalTo(0.5)
            make.left.equalToSuperview().offset(12)
            make.right.equalToSuperview()
        }
    }

}
