#include <QtWidgets/QApplication>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QWidget>
#include <QtWidgets/QDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QLabel>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QFrame>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QHeaderView>
#include <QtGui/QIntValidator>
#include <QtCore/Qt>
#include <QtCore/QFile>
#include <QtCore/QTextStream>
#include <QtCore/QFileInfo>
#include <QtCore/QDir>
#include <QtCore/QDateTime>
#include <QDir>
#include <QCoreApplication>
#include <QStandardPaths>


#include <string>
#include <vector>
#include <optional>
#include <fstream>
#include <sstream>
#include <iostream>
#include <random>
#include <ctime>
#include <algorithm>
#include <regex>
#include <chrono>
#include <iomanip>


static std::string app_data_path() {
    QString folder = "/Users/vishesh/Documents/innovative/build";

    QDir dir(folder);
    if (!dir.exists()) {
        dir.mkpath(".");  
    }
    return dir.absolutePath().toStdString();
}


static std::string USER_FILE        = app_data_path() + "/users.csv";
static std::string OTP_FILE         = app_data_path() + "/otps.csv";
static std::string ATTENDANCE_FILE  = app_data_path() + "/attendance.csv";

static void ensure_files_exist() {
    auto touch = [](const std::string& path, const std::string& header = "") {
        std::ifstream check(path);
        if (!check.good()) {
            std::ofstream ofs(path);
            if (!header.empty()) ofs << header << "\n";
            ofs.close();
            std::cout << "✅ Created: " << path << std::endl;
        }
    };

    touch(USER_FILE, "email,username,password");
    touch(OTP_FILE, "email,username,otp,timestamp");
    touch(ATTENDANCE_FILE, "username,timestamp");
}

struct UserRecord {
    std::string email;
    std::string username;
    std::string password;
};

template <typename T>
struct Node {
    T data;
    Node* next;
    explicit Node(const T& d) : data(d), next(nullptr) {}
};

template <typename T>
class LinkedList {
public:
    LinkedList() : head(nullptr) {}
    ~LinkedList() { clear(); }

    void insert(const T& data) {
        Node<T>* node = new Node<T>(data);
        node->next = head;
        head = node;
    }

    std::optional<T> find_by_username(const std::string& username) const {
        Node<T>* cur = head;
        while (cur) {
            if (cur->data.username == username) {
                return cur->data;
            }
            cur = cur->next;
        }
        return std::nullopt;
    }

    template <typename Func>
    void for_each(Func f) const {
        Node<T>* cur = head;
        while (cur) {
            f(cur->data);
            cur = cur->next;
        }
    }

    void clear() {
        Node<T>* cur = head;
        while (cur) {
            Node<T>* nx = cur->next;
            delete cur;
            cur = nx;
        }
        head = nullptr;
    }

private:
    Node<T>* head;
};


template <typename T>
class Stack {
public:
    void push(const T& item) { _data.push_back(item); }
    std::optional<T> pop() {
        if (_data.empty()) return std::nullopt;
        T v = _data.back();
        _data.pop_back();
        return v;
    }
    std::optional<T> peek() const {
        if (_data.empty()) return std::nullopt;
        return _data.back();
    }
    bool is_empty() const { return _data.empty(); }
private:
    std::vector<T> _data;
};

template <typename T>
class Queue {
public:
    void enqueue(const T& item) { _data.push_back(item); }
    std::optional<T> dequeue() {
        if (_data.empty()) return std::nullopt;
        T v = _data.front();
        _data.erase(_data.begin());
        return v;
    }

    std::optional<T> find_by_username(const std::string& username) const {
        for (const auto& item : _data) {
            if (item.username == username) return item;
        }
        return std::nullopt;
    }

    std::optional<T> remove_by_username(const std::string& username) {
        for (size_t i = 0; i < _data.size(); ++i) {
            if (_data[i].username == username) {
                T v = _data[i];
                _data.erase(_data.begin() + static_cast<long>(i));
                return v;
            }
        }
        return std::nullopt;
    }

    template <typename Pred>
    int remove_if(Pred p) {
        int removed = 0;
        std::vector<T> newvec;
        newvec.reserve(_data.size());
        for (auto& item : _data) {
            if (p(item)) { ++removed; }
            else { newvec.push_back(item); }
        }
        _data.swap(newvec);
        return removed;
    }


    const std::vector<T>& raw() const { return _data; }

private:
    std::vector<T> _data;
};


struct OTPEntry {
    std::string username;
    std::string email;
    std::string otp; 
    std::chrono::system_clock::time_point timestamp;
    int attempts = 0;
};

static inline bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

static inline std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

static inline std::string unquote(const std::string& s) {
    if (s.size() >= 2 && s.front() == '\"' && s.back() == '\"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}


static inline bool parse_csv_line(const std::string& line, std::vector<std::string>& fields) {
    fields.clear();
    std::string cur;
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '\"') {
            in_quotes = !in_quotes;
            cur.push_back(c);
        } else if (c == ',' && !in_quotes) {
            fields.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    fields.push_back(cur);
    return true;
}

static void load_users(LinkedList<UserRecord>& user_list) {
    user_list.clear();
    if (!file_exists(USER_FILE)) {
        return;
    }
    std::ifstream ifs(USER_FILE);
    if (!ifs) return;

    std::string line;
    bool header_skipped = false;
    while (std::getline(ifs, line)) {
        if (!header_skipped) {
            header_skipped = true;
            continue;
        }
        std::vector<std::string> fields;
        parse_csv_line(line, fields);
        if (fields.size() < 3) continue;
        UserRecord u;
        u.email = trim(unquote(fields[0]));
        u.username = trim(unquote(fields[1]));
        u.password = trim(unquote(fields[2]));
        user_list.insert(u);
    }
}

static void save_user(const UserRecord& user) {
    bool exists = file_exists(USER_FILE);
    std::ofstream ofs(USER_FILE, std::ios::app);
    if (!ofs) return;

    if (!exists) {
        ofs << "email,username,password\n";
    }
    ofs << user.email << "," << user.username << "," << user.password << "\n";
}


static bool is_valid_email(const std::string& email) {
    static const std::regex pattern(R"(^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$)", std::regex::icase);
    return std::regex_match(email, pattern);
}


class OTPManager {
public:
    explicit OTPManager(const LinkedList<UserRecord>* user_list)
        : user_list(user_list) {
        std::random_device rd;
        rng.seed(rd());
    }

   
    int generate_otp(const std::string& username) {
        purge_expired();
        auto user = user_list->find_by_username(username);
        if (!user.has_value()) return -1;
        std::uniform_int_distribution<int> dist(100000, 999999);
        int otp = dist(rng);
        OTPEntry entry{ user->username, user->email, std::to_string(otp), std::chrono::system_clock::now(), 0 };
        pending_queue.enqueue(entry);
        write_otp_file(user->email, user->username, entry.otp, entry.timestamp);

        return otp;
    }


    bool validate_otp(const std::string& username, const std::string& otp_input) {
        purge_expired();
        auto item = pending_queue.find_by_username(username);
        if (!item.has_value()) return false;

        auto now = std::chrono::system_clock::now();
        auto age_s = std::chrono::duration_cast<std::chrono::seconds>(now - item->timestamp).count();
        if (age_s > 120) {
     
            pending_queue.remove_by_username(username);
            return false;
        }

        if (item->otp == otp_input) {
            auto removed = pending_queue.remove_by_username(username);
            if (removed.has_value()) {
                used_stack.push(*removed);
                append_attendance_row(username, removed->timestamp);
            }
            return true;
        }

       
        auto removed = pending_queue.remove_by_username(username);
        if (!removed.has_value()) return false;
        removed->attempts += 1;
        if (removed->attempts >= 3) {
          
            return false;
        } else {
            pending_queue.enqueue(*removed);
            return false;
        }
    }

    int purge_expired() {
        auto now = std::chrono::system_clock::now();
        int removed = pending_queue.remove_if([&](const OTPEntry& e) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - e.timestamp).count();
            return age > 120;
        });
        return removed;
    }

    void append_attendance_row(const std::string& username, const std::chrono::system_clock::time_point& ts) {
        bool exists = file_exists(ATTENDANCE_FILE);
        std::ofstream ofs(ATTENDANCE_FILE, std::ios::app);
        if (!ofs) return;
        if (!exists) {
            ofs << "username,timestamp\n";
        }
        auto t = std::chrono::system_clock::to_time_t(ts);
        std::ostringstream ss;
        ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
        ofs << username << "," << ss.str() << "\n";
    }

    std::vector<std::pair<std::string, std::string>> read_attendance_for(const std::string& username) {
        std::vector<std::pair<std::string, std::string>> out;
        if (!file_exists(ATTENDANCE_FILE)) return out;
        std::ifstream ifs(ATTENDANCE_FILE);
        if (!ifs) return out;
        std::string line;
        bool header_skipped = false;
        while (std::getline(ifs, line)) {
            if (!header_skipped) { header_skipped = true; continue; }
            if (line.empty()) continue;
   
            size_t pos = line.find(',');
            if (pos == std::string::npos) continue;
            std::string user = trim(line.substr(0, pos));
            std::string ts = trim(line.substr(pos + 1));
            if (user == username) out.emplace_back(user, ts);
        }
        return out;
    }

private:
    const LinkedList<UserRecord>* user_list;
    Queue<OTPEntry> pending_queue;
    Stack<OTPEntry> used_stack;
    std::mt19937 rng;

    void write_otp_file(const std::string& email, const std::string& username,
                        const std::string& otp, const std::chrono::system_clock::time_point& ts) {
        bool exists = file_exists(OTP_FILE);
        std::ofstream ofs(OTP_FILE, std::ios::app);
        if (!ofs) return;

        // write header if file is empty
        if (!exists) {
            ofs << "email,username,otp,timestamp\n";
        }

        auto t = std::chrono::system_clock::to_time_t(ts);
        ofs << email << "," 
            << username << "," 
            << otp << "," 
            << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ") << "\n";
    }
};
class WelcomePage : public QWidget {
    Q_OBJECT
public:
    explicit WelcomePage(QWidget* parent = nullptr) : QWidget(parent) {
        setup_ui();
    }

    QPushButton* btn_register;
    QPushButton* btn_login;

private:
    void setup_ui() {
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(80, 80, 80, 80);
        layout->setSpacing(40);

        auto* title = new QLabel(QString::fromUtf8("✨ Welcome to OTP App ✨"));
        title->setAlignment(Qt::AlignCenter);
        title->setObjectName("title");
        title->setFixedHeight(120);

        auto* subtitle = new QLabel(QString::fromUtf8("Your secure OTP-based authentication system"));
        subtitle->setAlignment(Qt::AlignCenter);
        subtitle->setObjectName("subtitle");

        auto* btn_container = new QWidget();
        auto* btn_layout = new QHBoxLayout(btn_container);
        btn_layout->setSpacing(40);

        btn_register = new QPushButton("Register");
        btn_register->setObjectName("primary");
        btn_register->setFixedHeight(96);

        btn_login = new QPushButton("Login");
        btn_login->setObjectName("secondary");
        btn_login->setFixedHeight(96);

        btn_layout->addWidget(btn_register);
        btn_layout->addWidget(btn_login);

        layout->addStretch();
        layout->addWidget(title);
        layout->addWidget(subtitle);
        layout->addSpacing(20);
        layout->addWidget(btn_container);
        layout->addStretch();
    }
};

class RegisterDialog : public QDialog {
    Q_OBJECT
public:
    explicit RegisterDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle("Register");
        setup_ui();
    }

    QLineEdit* input_email;
    QLineEdit* input_username;
    QLineEdit* input_password;
    QPushButton* btn_next;

private:
    void setup_ui() {
        setFixedSize(840, 600);
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(40, 40, 40, 40);
        layout->setSpacing(24);

        auto* lbl = new QLabel("Create a new account");
        lbl->setAlignment(Qt::AlignCenter);
        lbl->setFixedHeight(60);
        lbl->setObjectName("dialogTitle");

        input_email = new QLineEdit();
        input_email->setPlaceholderText("Email");

        input_username = new QLineEdit();
        input_username->setPlaceholderText("Username");

        input_password = new QLineEdit();
        input_password->setPlaceholderText("Password");
        input_password->setEchoMode(QLineEdit::Password);

        btn_next = new QPushButton(QString::fromUtf8("Next ➡"));
        btn_next->setFixedHeight(80);
        btn_next->setObjectName("primary");

        layout->addWidget(lbl);
        layout->addWidget(input_email);
        layout->addWidget(input_username);
        layout->addWidget(input_password);
        layout->addStretch();
        layout->addWidget(btn_next);
    }
};

class LoginDialog : public QDialog {
    Q_OBJECT
public:
    explicit LoginDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle("Login");
        setup_ui();
    }

    QLineEdit* input_username;
    QLineEdit* input_password;
    QPushButton* btn_login;

private:
    void setup_ui() {
        setFixedSize(840, 480);
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(40, 40, 40, 40);
        layout->setSpacing(24);

        auto* lbl = new QLabel("Enter your credentials");
        lbl->setAlignment(Qt::AlignCenter);
        lbl->setFixedHeight(60);
        lbl->setObjectName("dialogTitle");

        input_username = new QLineEdit();
        input_username->setPlaceholderText("Username");

        input_password = new QLineEdit();
        input_password->setPlaceholderText("Password");
        input_password->setEchoMode(QLineEdit::Password);

        btn_login = new QPushButton(QString::fromUtf8("Login ➡"));
        btn_login->setFixedHeight(80);
        btn_login->setObjectName("primary");

        layout->addWidget(lbl);
        layout->addWidget(input_username);
        layout->addWidget(input_password);
        layout->addStretch();
        layout->addWidget(btn_login);
    }
};

class OTPDialog : public QDialog {
    Q_OBJECT
public:
    explicit OTPDialog(const QString& username, QWidget* parent = nullptr)
        : QDialog(parent), username(username) {
        setWindowTitle("Enter OTP");
        setup_ui();
    }

    QString username;
    QLineEdit* input_otp;
    QPushButton* btn_next;
    QPushButton* btn_cancel;

private:
    void setup_ui() {
        setFixedSize(840, 400);
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(40, 40, 40, 40);
        layout->setSpacing(24);

        auto* lbl = new QLabel(QString::fromUtf8("📨 OTP has been saved it file . Enter it below, ") + username + ".");
        lbl->setWordWrap(true);
        lbl->setAlignment(Qt::AlignCenter);
        lbl->setObjectName("dialogTitle");

        input_otp = new QLineEdit();
        input_otp->setPlaceholderText(QString::fromUtf8("🔢 6-digit OTP"));
        input_otp->setMaxLength(6);
        input_otp->setValidator(new QIntValidator(0, 999999, this));

        auto* btn_layout = new QHBoxLayout();
        btn_next = new QPushButton(QString::fromUtf8("Next ➡"));
        btn_next->setObjectName("primary");
        btn_next->setFixedHeight(80);
        btn_cancel = new QPushButton(QString::fromUtf8("Cancel ✖"));
        btn_cancel->setObjectName("secondary");
        btn_cancel->setFixedHeight(80);

        btn_layout->addWidget(btn_cancel);
        btn_layout->addWidget(btn_next);

        layout->addWidget(lbl);
        layout->addWidget(input_otp);
        layout->addStretch();
        layout->addLayout(btn_layout);
    }
};


class AttendanceDialog : public QDialog {
    Q_OBJECT
public:
    AttendanceDialog(const std::vector<std::pair<std::string, std::string>>& rows, QWidget* parent = nullptr)
        : QDialog(parent)
    {
        setWindowTitle("Attendance Records");
        setFixedSize(700, 480);
        auto* layout = new QVBoxLayout(this);
        table = new QTableWidget(this);
        table->setColumnCount(2);
        table->setHorizontalHeaderLabels(QStringList() << "Username" << "Timestamp");
        table->horizontalHeader()->setStretchLastSection(true);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->verticalHeader()->setVisible(false);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setRowCount(static_cast<int>(rows.size()));
        for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
            auto& r = rows[i];
            table->setItem(i, 0, new QTableWidgetItem(QString::fromStdString(r.first)));
            table->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(r.second)));
        }
        layout->addWidget(table);
        auto* btn_close = new QPushButton("Close");
        connect(btn_close, &QPushButton::clicked, this, &QDialog::accept);
        layout->addWidget(btn_close);
    }

private:
    QTableWidget* table;
};

class ChangePasswordDialog : public QDialog {
    Q_OBJECT
public:
    ChangePasswordDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle("Change Password");
        setFixedSize(640, 420);
        auto* layout = new QVBoxLayout(this);

        auto* lbl = new QLabel("Change your password");
        lbl->setAlignment(Qt::AlignCenter);
        lbl->setObjectName("dialogTitle");
        lbl->setFixedHeight(48);

        input_current = new QLineEdit();
        input_current->setPlaceholderText("Current password");
        input_current->setEchoMode(QLineEdit::Password);

        input_new = new QLineEdit();
        input_new->setPlaceholderText("New password");
        input_new->setEchoMode(QLineEdit::Password);

        input_confirm = new QLineEdit();
        input_confirm->setPlaceholderText("Confirm new password");
        input_confirm->setEchoMode(QLineEdit::Password);

        btn_change = new QPushButton("Change Password");
        btn_change->setObjectName("primary");

        layout->addWidget(lbl);
        layout->addWidget(input_current);
        layout->addWidget(input_new);
        layout->addWidget(input_confirm);
        layout->addStretch();
        layout->addWidget(btn_change);
    }

    QLineEdit* input_current;
    QLineEdit* input_new;
    QLineEdit* input_confirm;
    QPushButton* btn_change;
};

class DashboardPage : public QWidget {
    Q_OBJECT
public:
    DashboardPage(QWidget* parent = nullptr) : QWidget(parent) {
        setup_ui();
    }

    QLabel* lbl_welcome;
    QPushButton* btn_mark_attendance;
    QPushButton* btn_view_attendance;
    QPushButton* btn_change_password;
    QPushButton* btn_logout;

private:
    void setup_ui() {
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(40, 40, 40, 40);
        layout->setSpacing(20);

        lbl_welcome = new QLabel("Welcome, user!");
        lbl_welcome->setAlignment(Qt::AlignCenter);
        lbl_welcome->setFixedHeight(80);
        lbl_welcome->setObjectName("dialogTitle");

        btn_mark_attendance = new QPushButton("Mark Attendance");
        btn_mark_attendance->setFixedHeight(80);
        btn_mark_attendance->setObjectName("primary");

        btn_view_attendance = new QPushButton("View Attendance");
        btn_view_attendance->setFixedHeight(80);
        btn_view_attendance->setObjectName("secondary");

        btn_change_password = new QPushButton("Change Password");
        btn_change_password->setFixedHeight(80);
        btn_change_password->setObjectName("primary");

        btn_logout = new QPushButton("Logout");
        btn_logout->setFixedHeight(60);
        btn_logout->setObjectName("secondary");

        layout->addWidget(lbl_welcome);
        layout->addSpacing(10);
        layout->addWidget(btn_mark_attendance);
        layout->addWidget(btn_view_attendance);
        layout->addWidget(btn_change_password);
        layout->addStretch();
        layout->addWidget(btn_logout);
    }
};

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow() {
        setWindowTitle("OTP Management App");
        resize(1440, 920);
        setMinimumSize(1160, 760);

        {
            std::ifstream ifs(OTP_FILE);
            if (!ifs.good()) {
                std::ofstream ofs(OTP_FILE);
            }
        }
        {
            std::ifstream ifs(ATTENDANCE_FILE);
            if (!ifs.good()) {
                std::ofstream ofs(ATTENDANCE_FILE);
            }
        }

        load_users(users);
        otp_manager = new OTPManager(&users);

        setup_ui();
        apply_styles();
    }

    ~MainWindow() override {
        delete otp_manager;
    }

private:
    LinkedList<UserRecord> users;
    OTPManager* otp_manager;
    QStackedWidget* stacked;
    WelcomePage* page_welcome;


    DashboardPage* page_dashboard;
    QString current_user; 

    void setup_ui() {
        auto* central = new QWidget();
        setCentralWidget(central);

        auto* layout = new QVBoxLayout(central);
        layout->setContentsMargins(0, 0, 0, 0);

        auto* card = new QFrame();
        card->setObjectName("card");
        auto* card_layout = new QVBoxLayout(card);
        card_layout->setContentsMargins(40, 40, 40, 40);

        stacked = new QStackedWidget();
        page_welcome = new WelcomePage();
        stacked->addWidget(page_welcome);

        page_dashboard = new DashboardPage();
        stacked->addWidget(page_dashboard);

        card_layout->addWidget(stacked);

        layout->addStretch();
        layout->addWidget(card);
        layout->addStretch();

      
        connect(page_welcome->btn_register, &QPushButton::clicked, this, &MainWindow::open_register);
        connect(page_welcome->btn_login, &QPushButton::clicked, this, &MainWindow::open_login);

        connect(page_dashboard->btn_mark_attendance, &QPushButton::clicked, this, &MainWindow::on_mark_attendance);
        connect(page_dashboard->btn_view_attendance, &QPushButton::clicked, this, &MainWindow::on_view_attendance);
        connect(page_dashboard->btn_change_password, &QPushButton::clicked, this, &MainWindow::on_open_change_password);
        connect(page_dashboard->btn_logout, &QPushButton::clicked, this, &MainWindow::on_logout);
    }

    void apply_styles() {
        setStyleSheet(
            "QWidget{font-family: 'Segoe UI', Roboto, Arial; font-size:28px;}"
            "#card{background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #ffffff, stop:1 #f6f9ff); border-radius:40px; margin:40px;}"
            "#title{font-size:60px; font-weight:700; color:#2b2f6b}"
            "#subtitle{font-size:28px; color:#444}"
            "QPushButton#primary{background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #6a8cff, stop:1 #4b63d6); color:white; border:none; border-radius:24px; padding:20px; font-weight:600}"
            "QPushButton#primary:hover{background:#5a75e0}"
            "QPushButton#secondary{background: white; color:#4b63d6; border:4px solid #d1d9ff; border-radius:24px; padding:16px; font-weight:600}"
            "QPushButton#secondary:hover{background:#f1f4ff}"
            "QLabel#dialogTitle{font-size:32px; font-weight:600}"
            "QLineEdit{padding:20px; border-radius:16px; border:2px solidrgb(3, 3, 3); background:white; color:black}"
            "QMainWindow{background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #edf0ff, stop:1 #f7fbff)}"
        );
    }

private slots:

    void open_register() {
        RegisterDialog dlg(this);
        connect(dlg.btn_next, &QPushButton::clicked, [&]() { register_user(&dlg); });
        dlg.exec();
    }

    void register_user(RegisterDialog* dlg) {
        const QString email = dlg->input_email->text().trimmed();
        const QString username = dlg->input_username->text().trimmed();
        const QString password = dlg->input_password->text().trimmed();

        if (email.isEmpty() || username.isEmpty() || password.isEmpty()) {
            QMessageBox::warning(dlg, "Missing fields", "Please fill in all fields.");
            return;
        }

        if (!is_valid_email(email.toStdString())) {
            QMessageBox::warning(dlg, "Invalid Email", "Please enter a valid email address.");
            return;
        }

        auto existing = users.find_by_username(username.toStdString());
        if (existing.has_value()) {
            QMessageBox::warning(dlg, "Already exists", "Username already registered. Choose another.");
            return;
        }

        UserRecord user{ email.toStdString(), username.toStdString(), password.toStdString() };
        users.insert(user);
        save_user(user);

        QMessageBox::information(dlg, "Registered", "Registration successful. Click OK to return to welcome.");
        dlg->accept();
    }


    void open_login() {
        LoginDialog dlg(this);
        connect(dlg.btn_login, &QPushButton::clicked, [&]() { attempt_login(&dlg); });
        dlg.exec();
    }

    void attempt_login(LoginDialog* dlg) {
        const QString username = dlg->input_username->text().trimmed();
        const QString password = dlg->input_password->text().trimmed();

        if (username.isEmpty() || password.isEmpty()) {
            QMessageBox::warning(dlg, "Missing fields", "Please enter username and password.");
            return;
        }

        auto user = users.find_by_username(username.toStdString());
        if (!user.has_value() || user->password != password.toStdString()) {
            QMessageBox::warning(dlg, "Invalid", "Username or password incorrect.");
            return;
        }

        int otp = otp_manager->generate_otp(username.toStdString());
       
        QMessageBox::information(dlg, "OTP Sent",
            QString("A 6-digit OTP has been generated and saved to %1 for this account.").arg(OTP_FILE));

        dlg->accept();

        
        OTPDialog otp_dlg(username, this);
        connect(otp_dlg.btn_next, &QPushButton::clicked, [&]() { verify_otp_and_proceed(&otp_dlg); });
        connect(otp_dlg.btn_cancel, &QPushButton::clicked, [&]() { otp_dlg.reject(); });
        otp_dlg.exec();
    }


    void verify_otp_and_proceed(OTPDialog* dlg) {
        const QString otp_input = dlg->input_otp->text().trimmed();
        if (otp_input.isEmpty()) {
            QMessageBox::warning(dlg, "Missing OTP", "Please enter the 6-digit OTP.");
            return;
        }

        bool ok = otp_manager->validate_otp(dlg->username.toStdString(), otp_input.toStdString());
        if (ok) {
     
            current_user = dlg->username;
            page_dashboard->lbl_welcome->setText(QString("Welcome, %1!").arg(current_user));
            stacked->setCurrentWidget(page_dashboard);
            dlg->accept();
            QMessageBox::information(this, "Success", "Login Successful — welcome to the dashboard.");
        } else {
            QMessageBox::critical(dlg, "Failed", "OTP incorrect or expired.");
        }
    }

    void on_mark_attendance() {
        if (current_user.isEmpty()) {
            QMessageBox::warning(this, "Not logged in", "No logged-in user.");
            return;
        }
        auto now = std::chrono::system_clock::now();
        otp_manager->append_attendance_row(current_user.toStdString(), now);
        QMessageBox::information(this, "Attendance", "Attendance marked.");
    }

    void on_view_attendance() {
        if (current_user.isEmpty()) {
            QMessageBox::warning(this, "Not logged in", "No logged-in user.");
            return;
        }
        auto rows = otp_manager->read_attendance_for(current_user.toStdString());
        AttendanceDialog dlg(rows, this);
        dlg.exec();
    }

    void on_open_change_password() {
        if (current_user.isEmpty()) {
            QMessageBox::warning(this, "Not logged in", "No logged-in user.");
            return;
        }
        ChangePasswordDialog dlg(this);
        connect(dlg.btn_change, &QPushButton::clicked, [&]() {
            handle_change_password(&dlg);
        });
        dlg.exec();
    }

    
    void handle_change_password(ChangePasswordDialog* dlg) {
        QString cur = dlg->input_current->text();
        QString nw = dlg->input_new->text();
        QString cf = dlg->input_confirm->text();

        if (cur.isEmpty() || nw.isEmpty() || cf.isEmpty()) {
            QMessageBox::warning(dlg, "Missing fields", "Please fill in all fields.");
            return;
        }
        if (nw != cf) {
            QMessageBox::warning(dlg, "Mismatch", "New password and confirmation do not match.");
            return;
        }

        // load all users into vector
        std::vector<UserRecord> all;
        if (file_exists(USER_FILE)) {
            std::ifstream ifs(USER_FILE);
            std::string line;
            bool header_skipped = false;
            while (std::getline(ifs, line)) {
                if (!header_skipped) { header_skipped = true; continue; }
                if (line.empty()) continue;
                std::vector<std::string> fields;
                parse_csv_line(line, fields);
                if (fields.size() < 3) continue;
                UserRecord u;
                u.email = trim(unquote(fields[0]));
                u.username = trim(unquote(fields[1]));
                u.password = trim(unquote(fields[2]));
                all.push_back(u);
            }
        }

        bool found = false;
        for (auto& u : all) {
            if (u.username == current_user.toStdString()) {
                if (u.password != cur.toStdString()) {
                    QMessageBox::warning(dlg, "Invalid", "Current password is incorrect.");
                    return;
                }
                u.password = nw.toStdString();
                found = true;
                break;
            }
        }
        if (!found) {
            QMessageBox::warning(dlg, "Not found", "User not found (unexpected).");
            return;
        }

        // rewrite users.csv safely
        std::ofstream ofs(USER_FILE, std::ios::trunc);
        if (!ofs) {
            QMessageBox::critical(dlg, "Error", "Failed to write users file.");
            return;
        }
        ofs << "email,username,password\n";
        for (const auto& u : all) {
            ofs << u.email << "," << u.username << "," << u.password << "\n";
        }
        ofs.close();

        // reload in-memory users
        load_users(users);

        QMessageBox::information(dlg, "Changed", "Password changed successfully.");
        dlg->accept();
    }

    void on_logout() {
        current_user.clear();
        stacked->setCurrentWidget(page_welcome);
        QMessageBox::information(this, "Logged out", "You have been logged out.");
    }
};

#include "innovative-1.moc"


int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

   
    ensure_files_exist();

    std::cout << "📂 Data folder: " << app_data_path() << std::endl;

    MainWindow w;
    w.show();

    return app.exec();
}
