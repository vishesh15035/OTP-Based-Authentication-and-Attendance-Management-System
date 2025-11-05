# OTP-Based Authentication and Attendance Management System

A Qt-based desktop application for **secure login and attendance tracking using OTP verification**.  
Developed in **C++ (Qt5/Qt6)** using **CMake**.

---

## 🚀 Features
- Register and login with username, password, and email.
- OTP (One-Time Password) generation and validation.
- Automatic attendance marking after successful OTP.
- View attendance history.
- Change password functionality.
- Data stored in `.csv` files (no external database required).

---

## 🧰 Tech Stack
- **Language:** C++17  
- **Framework:** Qt5 / Qt6 (Widgets)  
- **Build System:** CMake  
- **UI:** Qt Dialogs and Layouts  
- **File Storage:** CSV files for users, OTPs, and attendance records

---

## ⚙️ Build Instructions

### Prerequisites
- CMake ≥ 3.16  
- Qt5 or Qt6 with Widgets module  
- A C++17 compiler (GCC, Clang, or MSVC)

### Build Steps
```bash
git clone https://github.com/vishesh15035/OTP-Based-Authentication-and-Attendance-Management-System.git
cd OTP-Based-Authentication-and-Attendance-Management-System
mkdir build && cd build
cmake ..
make
./bin/innovative-1
```

---

## 📁 File Outputs
| File | Description |
|------|--------------|
| `users.csv` | Stores registered user details |
| `otps.csv` | Temporary OTP records |
| `attendance.csv` | Logs attendance timestamps |

---

## 🧑‍💻 Author
**Vishesh**  
[LinkedIn](https://linkedin.com/in/your-link) • [GitHub](https://github.com/vishesh15035)

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
