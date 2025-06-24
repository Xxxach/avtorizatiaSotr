import tkinter as tk
from tkinter import messagebox, ttk
import bcrypt
import datetime
import uuid

users = {}

logs = []

roles_data = {
    'user': ['view_profile', 'change_password', 'view_notifications', 'access_support', 'view_calendar',
             'view_documents', 'view_personal_settings', 'manage_leave_requests'],
    'admin': ['manage_users', 'view_logs', 'view_stats', 'manage_roles', 'view_alerts', 'view_profile',
              'change_password', 'manage_announcements', 'view_user_activity', 'manage_system_config',
              'generate_reports']
}

notifications_list = [
    {'id': 1, 'message': 'Ваш пароль истекает через 7 дней!', 'read': False},
    {'id': 2, 'message': 'Новое обновление политик конфиденциальности.', 'read': True},
    {'id': 3, 'message': 'Система будет недоступна 25.06.2025 с 02:00 до 03:00 для планового обслуживания.',
     'read': False}
]

system_alerts = [
    {'id': 1, 'timestamp': '2025-06-20 10:05:00', 'level': 'CRITICAL',
     'message': 'Обнаружена подозрительная активность аккаунта "hacker_test" (5 неудачных попыток входа).'},
    {'id': 2, 'timestamp': '2025-06-21 14:30:00', 'level': 'WARNING',
     'message': 'Недостаточно места на диске сервера приложений.'},
    {'id': 3, 'timestamp': '2025-06-22 08:00:00', 'level': 'INFO',
     'message': 'Плановое обслуживание базы данных завершено успешно.'}
]

public_announcements = [
    {'id': 1, 'title': 'Добро пожаловать в компанию!', 'date': '2025-01-15',
     'content': 'Мы рады приветствовать новых сотрудников!'},
    {'id': 2, 'title': 'График праздников 2025', 'date': '2025-03-01',
     'content': 'Ознакомьтесь с утвержденным графиком праздничных дней на 2025 год.'},
    {'id': 3, 'title': 'Обновление корпоративного сайта', 'date': '2025-06-10',
     'content': 'Наш корпоративный сайт был обновлен. В ближайшее время ожидается новый функционал.'}
]

events_list = [
    {'id': 1, 'date': '2025-07-01', 'time': '10:00', 'title': 'Ежемесячное совещание отдела',
     'location': 'Конференц-зал А'},
    {'id': 2, 'date': '2025-07-05', 'time': '14:30', 'title': 'Вебинар: Новые технологии', 'location': 'Онлайн'},
    {'id': 3, 'date': '2025-07-10', 'time': '09:00', 'title': 'Корпоративный завтрак', 'location': 'Кухня'}
]

documents_list = [
    {'id': 1, 'title': 'Политика использования ИТ-ресурсов', 'version': '1.2', 'date': '2024-11-01',
     'link': 'policy_it_resources.pdf'},
    {'id': 2, 'title': 'Руководство по безопасности данных', 'version': '2.0', 'date': '2025-02-10',
     'link': 'data_security_guide.docx'},
    {'id': 3, 'title': 'Шаблон отчета по продажам', 'version': '1.0', 'date': '2025-05-20',
     'link': 'sales_report_template.xlsx'}
]

public_faq_data = [
    {'id': 1, 'question': 'Как получить доступ к корпоративной сети?',
     'answer': 'Доступ к корпоративной сети предоставляется всем новым сотрудникам автоматически после первой авторизации в системе.'},
    {'id': 2, 'question': 'Куда обратиться по вопросам заработной платы?',
     'answer': 'По вопросам заработной платы обращайтесь в отдел бухгалтерии или отправьте запрос по адресу payroll@company.com.'},
    {'id': 3, 'question': 'Как сбросить забытый пароль?',
     'answer': 'Нажмите кнопку "Забыли пароль?" на странице входа и следуйте инструкциям. Если проблема сохраняется, обратитесь в службу поддержки.'}
]

company_news_data = [
    {'id': 1, 'date': '2025-06-20', 'title': 'Новый рекорд продаж!',
     'content': 'Наша команда достигла нового исторического максимума по продажам в этом квартале!'},
    {'id': 2, 'date': '2025-06-15', 'title': 'Запуск нового проекта "Альфа"',
     'content': 'Успешно запущен пилотный проект "Альфа". Ожидаем отличных результатов!'},
    {'id': 3, 'date': '2025-06-01', 'title': 'День донора крови в офисе',
     'content': 'Спасибо всем, кто принял участие в корпоративной акции "День донора крови".'}
]

job_openings_data = [
    {'id': 1, 'title': 'Разработчик Python', 'department': 'ИТ-отдел', 'location': 'Москва', 'status': 'Открыта'},
    {'id': 2, 'title': 'Менеджер по продажам', 'department': 'Отдел продаж', 'location': 'Санкт-Петербург',
     'status': 'Открыта'},
    {'id': 3, 'title': 'Бухгалтер', 'department': 'Бухгалтерия', 'location': 'Москва', 'status': 'Открыта'}
]

leave_requests_data = [
    {'id': 1, 'username': 'employee1', 'start_date': '2025-08-01', 'end_date': '2025-08-14', 'status': 'Одобрено',
     'notes': 'Ежегодный отпуск'},
    {'id': 2, 'username': 'employee1', 'start_date': '2025-09-01', 'end_date': '2025-09-03', 'status': 'В ожидании',
     'notes': 'По семейным обстоятельствам'}
]

current_user = None


def hash_password(password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')


def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def log_action(action_type, username, details):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logs.append({
        'timestamp': timestamp,
        'type': action_type,
        'username': username,
        'details': details
    })
    print(f"LOG: [{timestamp}] Type: {action_type}, User: {username}, Details: {details}")
    if action_type == 'login_attempt' and "Неверный" in details:
        system_alerts.append({
            'id': len(system_alerts) + 1,
            'timestamp': timestamp,
            'level': 'WARNING',
            'message': f"Неудачная попытка входа для пользователя '{username}'. Детали: {details}"
        })


def show_message(title, message, is_error=False):
    if is_error:
        messagebox.showerror(title, message)
    else:
        messagebox.showinfo(title, message)


def initialize_test_data():
    if not users:
        admin_password = "admin_password123!"
        user_password = "user_password123!"

        users['admin'] = {
            'password_hash': hash_password(admin_password),
            'email': 'admin@company.com',
            'role': 'admin',
            'status': 'active',
            'full_name': 'Иван Иванов'
        }
        log_action('admin_action', 'SYSTEM', f"Добавлен администратор 'admin'")

        users['employee1'] = {
            'password_hash': hash_password(user_password),
            'email': 'employee1@company.com',
            'role': 'user',
            'status': 'active',
            'full_name': 'Петр Петров'
        }
        log_action('admin_action', 'SYSTEM', f"Добавлен сотрудник 'employee1'")

        users['blocked_user'] = {
            'password_hash': hash_password("blocked123!"),
            'email': 'blocked@company.com',
            'role': 'user',
            'status': 'blocked',
            'full_name': 'Анна Заблокированная'
        }
        log_action('admin_action', 'SYSTEM', f"Добавлен заблокированный пользователь 'blocked_user'")

    print("Тестовые данные инициализированы.")
    print("Доступные пользователи:", list(users.keys()))


class AuthApp:
    def __init__(self, master):
        self.master = master
        master.title("Приложение авторизации сотрудников")
        master.geometry("1000x700")
        master.configure(bg='#2e2e2e')

        self.mfa_enabled = tk.BooleanVar(value=False)

        s = ttk.Style()
        s.theme_use('clam')

        s.configure('.', background='#2e2e2e', foreground='#ffffff', font=('Inter', 12))
        s.configure('TFrame', background='#3c3c3c', borderwidth=0, relief="flat")
        s.configure('TLabel', background='#3c3c3c', foreground='#ffffff', font=('Inter', 12))
        s.configure('TEntry', fieldbackground='#5a5a5a', foreground='#ffffff', borderwidth=1,
                    relief="solid")
        s.configure('TButton', font=('Inter', 12, 'bold'), padding=10, background='#4a4a4a', foreground='#ffffff',
                    relief="flat", borderwidth=0)
        s.map('TButton',
              background=[('active', '#6a6a6a'), ('!disabled', '#4a4a4a')],
              foreground=[('active', '#ffffff'), ('!disabled', '#ffffff')])

        s.configure("Treeview",
                    background="#4a4a4a",
                    foreground="#ffffff",
                    rowheight=25,
                    fieldbackground="#4a4a4a")
        s.map("Treeview", background=[('selected', '#6a6a6a')])
        s.configure("Treeview.Heading",
                    background="#5a5a5a",
                    foreground="#ffffff",
                    font=('Inter', 12, 'bold'))

        s.configure("TNotebook", background="#3c3c3c", borderwidth=0)
        s.configure("TNotebook.Tab", background="#4a4a4a", foreground="#ffffff", padding=[10, 5])
        s.map("TNotebook.Tab",
              background=[('selected', '#5a5a5a'), ('active', '#6a6a6a')],
              foreground=[('selected', '#ffffff'), ('active', '#ffffff')])
        s.configure("TCombobox", fieldbackground='#5a5a5a', foreground='#ffffff',
                    background='#4a4a4a')
        s.configure("TCheckbutton", background='#3c3c3c', foreground='#ffffff')

        self.frames = {}
        self.create_login_ui()
        initialize_test_data()

    def show_frame(self, frame_name):
        for name, frame in self.frames.items():
            if name == frame_name:
                frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            else:
                frame.pack_forget()

    def create_login_ui(self):
        self.login_frame = ttk.Frame(self.master, padding="30 30 30 30")
        self.frames['login'] = self.login_frame

        ttk.Label(self.login_frame, text="Вход в систему", font=('Inter', 18, 'bold')).pack(pady=20)

        ttk.Label(self.login_frame, text="Логин:").pack(anchor='w', pady=(10, 0))
        self.username_entry = ttk.Entry(self.login_frame, width=40, font=('Inter', 12))
        self.username_entry.pack(pady=5)

        ttk.Label(self.login_frame, text="Пароль:").pack(anchor='w', pady=(10, 0))
        self.password_entry = ttk.Entry(self.login_frame, show="*", width=40, font=('Inter', 12))
        self.password_entry.pack(pady=5)

        ttk.Button(self.login_frame, text="Войти", command=self.login).pack(pady=20)

        ttk.Button(self.login_frame, text="Забыли пароль?", command=self.forgot_password).pack(pady=5)

        ttk.Button(self.login_frame, text="Публичный доступ", command=self.show_public_dashboard).pack(pady=10)

        self.show_frame('login')

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            show_message("Ошибка входа", "Пожалуйста, введите логин и пароль.", is_error=True)
            log_action('login_attempt', username, "Пустые поля логина/пароля")
            return

        user_data = users.get(username)

        if user_data:
            if user_data['status'] == 'blocked':
                show_message("Ошибка входа", "Ваша учетная запись заблокирована. Обратитесь к администратору.",
                             is_error=True)
                log_action('login_attempt', username, "Учетная запись заблокирована")
                return

            if check_password(password, user_data['password_hash']):
                global current_user
                current_user = username
                show_message("Вход выполнен", f"Добро пожаловать, {user_data['full_name']}!")
                log_action('login_success', username, "Успешный вход")

                self.username_entry.delete(0, tk.END)
                self.password_entry.delete(0, tk.END)

                if self.mfa_enabled.get():
                    self.verify_mfa(username, user_data['role'])
                else:
                    if user_data['role'] == 'admin':
                        self.show_admin_dashboard()
                    else:
                        self.show_user_dashboard()
            else:
                show_message("Ошибка входа", "Неверный логин или пароль.", is_error=True)
                log_action('login_attempt', username, "Неверный пароль")
        else:
            show_message("Ошибка входа", "Неверный логин или пароль.", is_error=True)
            log_action('login_attempt', username, "Пользователь не найден")

    def verify_mfa(self, username, role):
        dialog = tk.Toplevel(self.master)
        dialog.title("Подтверждение MFA")
        dialog.transient(self.master)
        dialog.grab_set()
        dialog.configure(bg='#3c3c3c')

        ttk.Label(dialog, text="Введите код MFA:").pack(pady=10)
        mfa_code_entry = ttk.Entry(dialog, width=30, font=('Inter', 12))
        mfa_code_entry.pack(pady=5)

        def submit_mfa():
            code = mfa_code_entry.get()
            if code == "123456":
                show_message("MFA", "Код MFA подтвержден успешно!")
                dialog.destroy()
                if role == 'admin':
                    self.show_admin_dashboard()
                else:
                    self.show_user_dashboard()
            else:
                show_message("Ошибка MFA", "Неверный код MFA. Попробуйте снова.", is_error=True)
                log_action('login_attempt', username, "Неверный код MFA")
                mfa_code_entry.delete(0, tk.END)

        ttk.Button(dialog, text="Подтвердить", command=submit_mfa).pack(pady=10)
        ttk.Button(dialog, text="Отмена", command=lambda: dialog.destroy()).pack(pady=5)

    def forgot_password(self):
        show_message("Восстановление пароля",
                     "Функция восстановления пароля находится в разработке. Пожалуйста, обратитесь к администратору.")

    def create_change_password_ui(self, parent_frame):
        change_password_frame = ttk.Frame(parent_frame, padding="20 20 20 20", relief=tk.GROOVE, borderwidth=2)
        change_password_frame.pack(pady=20, padx=20, fill=tk.X)

        ttk.Label(change_password_frame, text="Смена пароля", font=('Inter', 14, 'bold')).pack(pady=10)

        ttk.Label(change_password_frame, text="Текущий пароль:").pack(anchor='w', pady=(5, 0))
        self.current_password_entry = ttk.Entry(change_password_frame, show="*", width=30, font=('Inter', 12))
        self.current_password_entry.pack(pady=2)

        ttk.Label(change_password_frame, text="Новый пароль:").pack(anchor='w', pady=(5, 0))
        self.new_password_entry = ttk.Entry(change_password_frame, show="*", width=30, font=('Inter', 12))
        self.new_password_entry.pack(pady=2)

        ttk.Label(change_password_frame, text="Повторите новый пароль:").pack(anchor='w', pady=(5, 0))
        self.confirm_password_entry = ttk.Entry(change_password_frame, show="*", width=30, font=('Inter', 12))
        self.confirm_password_entry.pack(pady=2)

        ttk.Button(change_password_frame, text="Сменить пароль", command=self.change_password).pack(pady=15)

    def change_password(self):
        if not current_user:
            show_message("Ошибка", "Вы не авторизованы.", is_error=True)
            return

        current_pass = self.current_password_entry.get()
        new_pass = self.new_password_entry.get()
        confirm_pass = self.confirm_password_entry.get()

        user_data = users.get(current_user)

        if not check_password(current_pass, user_data['password_hash']):
            show_message("Ошибка", "Неверный текущий пароль.", is_error=True)
            return

        if new_pass != confirm_pass:
            show_message("Ошибка", "Новый пароль и подтверждение не совпадают.", is_error=True)
            return

        if len(new_pass) < 8 or \
                not any(c.isupper() for c in new_pass) or \
                not any(c.islower() for c in new_pass) or \
                not any(c.isdigit() for c in new_pass) or \
                not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in new_pass):
            show_message("Ошибка",
                         "Пароль должен содержать не менее 8 символов, включая заглавные и строчные буквы, цифры и специальные символы.",
                         is_error=True)
            return

        users[current_user]['password_hash'] = hash_password(new_pass)
        log_action('user_action', current_user, "Пароль успешно изменен")
        show_message("Успех", "Пароль успешно изменен!")
        self.current_password_entry.delete(0, tk.END)
        self.new_password_entry.delete(0, tk.END)
        self.confirm_password_entry.delete(0, tk.END)

    def show_user_dashboard(self):
        self.user_dashboard_frame = ttk.Frame(self.master, padding="20 20 20 20")
        self.frames['user_dashboard'] = self.user_dashboard_frame

        ttk.Label(self.user_dashboard_frame, text=f"Добро пожаловать, {users[current_user]['full_name']}!",
                  font=('Inter', 16, 'bold')).pack(pady=20)

        self.user_notebook = ttk.Notebook(self.user_dashboard_frame)
        self.user_notebook.pack(expand=True, fill=tk.BOTH, pady=10)

        self.user_profile_tab = ttk.Frame(self.user_notebook, padding="10")
        self.user_password_tab = ttk.Frame(self.user_notebook, padding="10")
        self.user_notifications_tab = ttk.Frame(self.user_notebook, padding="10")
        self.user_calendar_tab = ttk.Frame(self.user_notebook, padding="10")
        self.user_documents_tab = ttk.Frame(self.user_notebook, padding="10")
        self.user_leave_tab = ttk.Frame(self.user_notebook, padding="10")
        self.user_settings_tab = ttk.Frame(self.user_notebook, padding="10")
        self.user_support_tab = ttk.Frame(self.user_notebook, padding="10")

        self.user_notebook.add(self.user_profile_tab, text="Профиль")
        self.user_notebook.add(self.user_password_tab, text="Смена пароля")
        self.user_notebook.add(self.user_notifications_tab, text="Уведомления")
        self.user_notebook.add(self.user_calendar_tab, text="Календарь")
        self.user_notebook.add(self.user_documents_tab, text="Документы")
        self.user_notebook.add(self.user_leave_tab, text="Заявки на отпуск")
        self.user_notebook.add(self.user_settings_tab, text="Настройки")
        self.user_notebook.add(self.user_support_tab, text="Поддержка")

        self.create_user_profile_ui(self.user_profile_tab)
        self.create_change_password_ui(self.user_password_tab)
        self.create_user_notifications_ui(self.user_notifications_tab)
        self.create_user_calendar_ui(self.user_calendar_tab)
        self.create_user_documents_ui(self.user_documents_tab)
        self.create_user_leave_ui(self.user_leave_tab)
        self.create_user_settings_ui(self.user_settings_tab)
        self.create_user_support_ui(self.user_support_tab)

        ttk.Button(self.user_dashboard_frame, text="Выйти", command=self.logout).pack(pady=30)
        self.show_frame('user_dashboard')

    def create_user_profile_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Ваши данные", font=('Inter', 14, 'bold')).pack(pady=10)

        user_data = users.get(current_user, {})
        ttk.Label(parent_frame, text=f"Логин: {current_user}").pack(anchor='w', pady=2)
        ttk.Label(parent_frame, text=f"ФИО: {user_data.get('full_name', 'Не указано')}").pack(anchor='w', pady=2)
        ttk.Label(parent_frame, text=f"Email: {user_data.get('email', 'Не указано')}").pack(anchor='w', pady=2)
        ttk.Label(parent_frame, text=f"Роль: {user_data.get('role', 'Не указано')}").pack(anchor='w', pady=2)
        ttk.Label(parent_frame, text=f"Статус: {user_data.get('status', 'Не указано')}").pack(anchor='w', pady=2)

    def create_user_notifications_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Ваши уведомления", font=('Inter', 14, 'bold')).pack(pady=10)

        self.notifications_tree = ttk.Treeview(parent_frame, columns=("ID", "Message", "Read"), show="headings")
        self.notifications_tree.heading("ID", text="ID")
        self.notifications_tree.heading("Message", text="Сообщение")
        self.notifications_tree.heading("Read", text="Прочитано")

        self.notifications_tree.column("ID", width=50, anchor=tk.CENTER)
        self.notifications_tree.column("Message", width=400, anchor=tk.W)
        self.notifications_tree.column("Read", width=80, anchor=tk.CENTER)

        self.notifications_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.notifications_tree.yview)
        self.notifications_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.notifications_tree.config(yscrollcommand=scrollbar.set)

        self.update_notifications_list()

        button_frame = ttk.Frame(parent_frame)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Отметить как прочитанное", command=self.mark_notification_as_read).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Удалить уведомление", command=self.delete_notification).pack(side=tk.LEFT,
                                                                                                    padx=5)
        ttk.Button(button_frame, text="Обновить", command=self.update_notifications_list).pack(side=tk.LEFT, padx=5)

    def update_notifications_list(self):
        for item in self.notifications_tree.get_children():
            self.notifications_tree.delete(item)

        for notif in notifications_list:
            read_status = "Да" if notif['read'] else "Нет"
            self.notifications_tree.insert("", tk.END, iid=notif['id'],
                                           values=(notif['id'], notif['message'], read_status))

    def mark_notification_as_read(self):
        selected_item = self.notifications_tree.selection()
        if not selected_item:
            show_message("Ошибка", "Пожалуйста, выберите уведомление.", is_error=True)
            return

        notif_id = int(selected_item[0])
        for notif in notifications_list:
            if notif['id'] == notif_id:
                notif['read'] = True
                log_action('user_action', current_user, f"Уведомление '{notif['message']}' отмечено как прочитанное.")
                show_message("Успех", "Уведомление отмечено как прочитанное.")
                self.update_notifications_list()
                return
        show_message("Ошибка", "Уведомление не найдено.", is_error=True)

    def delete_notification(self):
        selected_item = self.notifications_tree.selection()
        if not selected_item:
            show_message("Ошибка", "Пожалуйста, выберите уведомление для удаления.", is_error=True)
            return

        notif_id = int(selected_item[0])
        global notifications_list
        initial_len = len(notifications_list)
        notifications_list = [notif for notif in notifications_list if notif['id'] != notif_id]
        if len(notifications_list) < initial_len:
            log_action('user_action', current_user, f"Уведомление с ID {notif_id} удалено.")
            show_message("Успех", "Уведомление удалено.")
            self.update_notifications_list()
        else:
            show_message("Ошибка", "Уведомление не найдено.", is_error=True)

    def create_user_calendar_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Предстоящие события", font=('Inter', 14, 'bold')).pack(pady=10)

        self.events_tree = ttk.Treeview(parent_frame, columns=("Date", "Time", "Title", "Location"), show="headings")
        self.events_tree.heading("Date", text="Дата")
        self.events_tree.heading("Time", text="Время")
        self.events_tree.heading("Title", text="Название")
        self.events_tree.heading("Location", text="Место")

        self.events_tree.column("Date", width=100, anchor=tk.W)
        self.events_tree.column("Time", width=80, anchor=tk.CENTER)
        self.events_tree.column("Title", width=250, anchor=tk.W)
        self.events_tree.column("Location", width=150, anchor=tk.W)

        self.events_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.events_tree.config(yscrollcommand=scrollbar.set)

        self.update_events_list()
        ttk.Button(parent_frame, text="Обновить события", command=self.update_events_list).pack(pady=10)

    def update_events_list(self):
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        for event in events_list:
            self.events_tree.insert("", tk.END,
                                    values=(event['date'], event['time'], event['title'], event['location']))

    def create_user_documents_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Внутренние документы", font=('Inter', 14, 'bold')).pack(pady=10)

        self.documents_tree = ttk.Treeview(parent_frame, columns=("Title", "Version", "Date", "Link"), show="headings")
        self.documents_tree.heading("Title", text="Название")
        self.documents_tree.heading("Version", text="Версия")
        self.documents_tree.heading("Date", text="Дата")
        self.documents_tree.heading("Link", text="Ссылка")

        self.documents_tree.column("Title", width=200, anchor=tk.W)
        self.documents_tree.column("Version", width=80, anchor=tk.CENTER)
        self.documents_tree.column("Date", width=100, anchor=tk.W)
        self.documents_tree.column("Link", width=150, anchor=tk.W)

        self.documents_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.documents_tree.yview)
        self.documents_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.documents_tree.config(yscrollcommand=scrollbar.set)

        self.update_documents_list()
        ttk.Button(parent_frame, text="Обновить документы", command=self.update_documents_list).pack(pady=10)
        ttk.Button(parent_frame, text="Скачать (заглушка)",
                   command=lambda: show_message("Скачивание", "Функция скачивания пока не реализована.")).pack(pady=5)

    def update_documents_list(self):
        for item in self.documents_tree.get_children():
            self.documents_tree.delete(item)
        for doc in documents_list:
            self.documents_tree.insert("", tk.END, values=(doc['title'], doc['version'], doc['date'], doc['link']))

    def create_user_leave_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Мои заявки на отпуск", font=('Inter', 14, 'bold')).pack(pady=10)

        form_frame = ttk.Frame(parent_frame, padding="10")
        form_frame.pack(fill=tk.X, pady=5)

        ttk.Label(form_frame, text="Начальная дата (ГГГГ-ММ-ДД):").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        self.leave_start_date_entry = ttk.Entry(form_frame, width=20)
        self.leave_start_date_entry.grid(row=0, column=1, padx=5, pady=2)
        self.leave_start_date_entry.insert(0, datetime.date.today().strftime("%Y-%m-%d"))

        ttk.Label(form_frame, text="Конечная дата (ГГГГ-ММ-ДД):").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        self.leave_end_date_entry = ttk.Entry(form_frame, width=20)
        self.leave_end_date_entry.grid(row=1, column=1, padx=5, pady=2)
        self.leave_end_date_entry.insert(0, (datetime.date.today() + datetime.timedelta(days=7)).strftime("%Y-%m-%d"))

        ttk.Label(form_frame, text="Примечания:").grid(row=2, column=0, sticky='w', padx=5, pady=2)
        self.leave_notes_entry = ttk.Entry(form_frame, width=40)
        self.leave_notes_entry.grid(row=2, column=1, padx=5, pady=2)

        ttk.Button(form_frame, text="Подать заявку", command=self.submit_leave_request).grid(row=3, column=0,
                                                                                             columnspan=2, pady=10)

        self.leave_tree = ttk.Treeview(parent_frame, columns=("Start Date", "End Date", "Status", "Notes"),
                                       show="headings")
        self.leave_tree.heading("Start Date", text="Начало")
        self.leave_tree.heading("End Date", text="Конец")
        self.leave_tree.heading("Status", text="Статус")
        self.leave_tree.heading("Notes", text="Примечания")

        self.leave_tree.column("Start Date", width=100, anchor=tk.W)
        self.leave_tree.column("End Date", width=100, anchor=tk.W)
        self.leave_tree.column("Status", width=100, anchor=tk.CENTER)
        self.leave_tree.column("Notes", width=250, anchor=tk.W)

        self.leave_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.leave_tree.yview)
        self.leave_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.leave_tree.config(yscrollcommand=scrollbar.set)

        self.update_leave_requests_list()
        ttk.Button(parent_frame, text="Обновить заявки", command=self.update_leave_requests_list).pack(pady=10)

    def submit_leave_request(self):
        start_date_str = self.leave_start_date_entry.get()
        end_date_str = self.leave_end_date_entry.get()
        notes = self.leave_notes_entry.get()

        try:
            start_date = datetime.datetime.strptime(start_date_str, "%Y-%m-%d").date()
            end_date = datetime.datetime.strptime(end_date_str, "%Y-%m-%d").date()
            if start_date > end_date:
                show_message("Ошибка", "Начальная дата не может быть позже конечной.", is_error=True)
                return
        except ValueError:
            show_message("Ошибка", "Неверный формат даты. Используйте ГГГГ-ММ-ДД.", is_error=True)
            return

        new_id = max([r['id'] for r in leave_requests_data]) + 1 if leave_requests_data else 1
        leave_requests_data.append({
            'id': new_id,
            'username': current_user,
            'start_date': start_date_str,
            'end_date': end_date_str,
            'status': 'В ожидании',
            'notes': notes
        })
        log_action('user_action', current_user, f"Подана заявка на отпуск с {start_date_str} по {end_date_str}")
        show_message("Успех", "Заявка на отпуск успешно подана.")
        self.leave_notes_entry.delete(0, tk.END)
        self.update_leave_requests_list()

    def update_leave_requests_list(self):
        for item in self.leave_tree.get_children():
            self.leave_tree.delete(item)

        for req in leave_requests_data:
            if req['username'] == current_user:
                self.leave_tree.insert("", tk.END,
                                       values=(req['start_date'], req['end_date'], req['status'], req['notes']))

    def create_user_settings_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Личные настройки", font=('Inter', 14, 'bold')).pack(pady=10)
        ttk.Label(parent_frame, text="Здесь будут расположены настройки вашего профиля, уведомлений и т.д.",
                  wraplength=500).pack(pady=20)
        ttk.Button(parent_frame, text="Сохранить настройки (заглушка)", command=lambda: show_message("Настройки",
                                                                                                     "Функционал сохранения личных настроек пока не реализован.")).pack(
            pady=10)

    def create_user_support_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Служба поддержки", font=('Inter', 14, 'bold')).pack(pady=10)
        ttk.Label(parent_frame, text="Если у вас возникли вопросы или проблемы, пожалуйста, свяжитесь с нами:",
                  wraplength=500).pack(pady=10)
        ttk.Label(parent_frame, text="Email: support@company.com").pack(anchor='w', pady=2)
        ttk.Label(parent_frame, text="Телефон: +123 456 7890").pack(anchor='w', pady=2)
        ttk.Label(parent_frame, text="Часы работы: Пн-Пт, 9:00 - 18:00").pack(anchor='w', pady=2)

    def show_admin_dashboard(self):
        self.admin_dashboard_frame = ttk.Frame(self.master, padding="20 20 20 20")
        self.frames['admin_dashboard'] = self.admin_dashboard_frame

        ttk.Label(self.admin_dashboard_frame, text=f"Панель администратора ({users[current_user]['full_name']})",
                  font=('Inter', 16, 'bold')).pack(pady=20)

        self.notebook = ttk.Notebook(self.admin_dashboard_frame)
        self.notebook.pack(expand=True, fill=tk.BOTH, pady=10)

        self.users_tab = ttk.Frame(self.notebook, padding="10")
        self.user_activity_tab = ttk.Frame(self.notebook, padding="10")
        self.logs_tab = ttk.Frame(self.notebook, padding="10")
        self.stats_tab = ttk.Frame(self.notebook, padding="10")
        self.roles_tab = ttk.Frame(self.notebook, padding="10")
        self.alerts_tab = ttk.Frame(self.notebook, padding="10")
        self.announcements_management_tab = ttk.Frame(self.notebook, padding="10")
        self.admin_system_config_tab = ttk.Frame(self.notebook, padding="10")
        self.admin_reports_tab = ttk.Frame(self.notebook, padding="10")
        self.settings_tab = ttk.Frame(self.notebook, padding="10")

        self.notebook.add(self.users_tab, text="Управление пользователями")
        self.notebook.add(self.user_activity_tab, text="Активность пользователей")
        self.notebook.add(self.logs_tab, text="Журнал действий")
        self.notebook.add(self.stats_tab, text="Статистика")
        self.notebook.add(self.roles_tab, text="Управление ролями")
        self.notebook.add(self.alerts_tab, text="Системные оповещения")
        self.notebook.add(self.announcements_management_tab, text="Управление объявлениями")
        self.notebook.add(self.admin_system_config_tab, text="Конфигурация системы")
        self.notebook.add(self.admin_reports_tab, text="Отчеты")
        self.notebook.add(self.settings_tab, text="Настройки")

        self.create_manage_users_ui(self.users_tab)
        self.create_user_activity_ui(self.user_activity_tab)
        self.create_view_logs_ui(self.logs_tab)
        self.create_admin_stats_ui(self.stats_tab)
        self.create_manage_roles_ui(self.roles_tab)
        self.create_system_alerts_ui(self.alerts_tab)
        self.create_manage_announcements_ui(self.announcements_management_tab)
        self.create_admin_system_config_ui(self.admin_system_config_tab)
        self.create_admin_reports_ui(self.admin_reports_tab)
        self.create_admin_settings_ui(self.settings_tab)

        ttk.Button(self.admin_dashboard_frame, text="Выйти", command=self.logout).pack(pady=20)
        self.show_frame('admin_dashboard')

    def logout(self):
        global current_user
        if current_user:
            log_action('logout', current_user, "Выход из системы")
        current_user = None
        show_message("Выход", "Вы успешно вышли из системы.")
        self.show_frame('login')

    def create_manage_users_ui(self, parent_frame):
        button_frame = ttk.Frame(parent_frame)
        button_frame.pack(pady=10, fill=tk.X)

        ttk.Button(button_frame, text="Добавить пользователя", command=self.add_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Редактировать пользователя", command=self.edit_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Блокировать/Разблокировать", command=self.toggle_user_status).pack(side=tk.LEFT,
                                                                                                          padx=5)
        ttk.Button(button_frame, text="Удалить пользователя", command=self.delete_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Обновить список", command=self.update_user_list).pack(side=tk.RIGHT, padx=5)

        self.user_tree = ttk.Treeview(parent_frame, columns=("Full Name", "Email", "Role", "Status"), show="headings")
        self.user_tree.heading("Full Name", text="ФИО")
        self.user_tree.heading("Email", text="Email")
        self.user_tree.heading("Role", text="Роль")
        self.user_tree.heading("Status", text="Статус")

        self.user_tree.column("Full Name", width=150, anchor=tk.W)
        self.user_tree.column("Email", width=150, anchor=tk.W)
        self.user_tree.column("Role", width=80, anchor=tk.CENTER)
        self.user_tree.column("Status", width=80, anchor=tk.CENTER)

        self.user_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.user_tree.yview)
        self.user_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.user_tree.config(yscrollcommand=scrollbar.set)

        self.update_user_list()

    def update_user_list(self):
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)

        for username, data in users.items():
            self.user_tree.insert("", tk.END, iid=username,
                                  values=(data['full_name'], data['email'], data['role'], data['status']))
        if hasattr(self, 'user_activity_user_select'):
            self.user_activity_user_select['values'] = list(users.keys())

    def add_user(self):
        self.create_add_edit_user_dialog("add")

    def edit_user(self):
        selected_item = self.user_tree.selection()
        if not selected_item:
            show_message("Ошибка", "Пожалуйста, выберите пользователя для редактирования.", is_error=True)
            return
        username = selected_item[0]
        self.create_add_edit_user_dialog("edit", username)

    def create_add_edit_user_dialog(self, mode, username=None):
        dialog = tk.Toplevel(self.master)
        dialog.title("Добавить пользователя" if mode == "add" else "Редактировать пользователя")
        dialog.transient(self.master)
        dialog.grab_set()
        dialog.configure(bg='#3c3c3c')

        form_frame = ttk.Frame(dialog, padding="20 20 20 20")
        form_frame.pack()

        labels = ["Логин:", "ФИО:", "Email:", "Роль:"]
        entries = {}

        for i, label_text in enumerate(labels):
            ttk.Label(form_frame, text=label_text).grid(row=i, column=0, sticky='w', pady=5, padx=5)
            if label_text == "Роль:":
                self.role_var = tk.StringVar(form_frame)
                role_options = list(roles_data.keys())
                role_combobox = ttk.Combobox(form_frame, textvariable=self.role_var, values=role_options,
                                             state="readonly", font=('Inter', 12), width=30)
                role_combobox.grid(row=i, column=1, pady=5, padx=5)
                role_combobox.set("user")
                entries['role'] = role_combobox
            else:
                entry = ttk.Entry(form_frame, width=30, font=('Inter', 12))
                entry.grid(row=i, column=1, pady=5, padx=5)
                entries[label_text.replace(":", "").lower().replace(" ", "_")] = entry

        if mode == "add":
            ttk.Label(form_frame, text="Пароль:").grid(row=len(labels), column=0, sticky='w', pady=5, padx=5)
            password_entry = ttk.Entry(form_frame, show="*", width=30, font=('Inter', 12))
            password_entry.grid(row=len(labels), column=1, pady=5, padx=5)
            entries['password'] = password_entry

        if mode == "edit" and username:
            user_data = users.get(username)
            if user_data:
                entries['логин'].insert(0, username)
                entries['логин'].config(state='readonly')
                entries['фто'].insert(0, user_data.get('full_name', ''))
                entries['email'].insert(0, user_data.get('email', ''))
                self.role_var.set(user_data.get('role', 'user'))
            else:
                show_message("Ошибка", "Пользователь не найден.", is_error=True)
                dialog.destroy()
                return

        def save_user():
            login = entries['логин'].get()
            full_name = entries['фто'].get()
            email = entries['email'].get()
            role = self.role_var.get()
            password = entries['password'].get() if mode == "add" else None

            if not login or not full_name or not email or not role:
                show_message("Ошибка", "Пожалуйста, заполните все поля.", is_error=True)
                return

            if mode == "add":
                if not password:
                    show_message("Ошибка", "Пожалуйста, введите пароль для нового пользователя.", is_error=True)
                    return
                if login in users:
                    show_message("Ошибка", "Пользователь с таким логином уже существует.", is_error=True)
                    return
                users[login] = {
                    'password_hash': hash_password(password),
                    'email': email,
                    'role': role,
                    'status': 'active',
                    'full_name': full_name
                }
                log_action('admin_action', current_user, f"Добавлен пользователь: {login}")
                show_message("Успех", "Пользователь успешно добавлен.")
            elif mode == "edit":
                if username not in users:
                    show_message("Ошибка", "Редактируемый пользователь не найден.", is_error=True)
                    return
                users[username]['full_name'] = full_name
                users[username]['email'] = email
                users[username]['role'] = role
                log_action('admin_action', current_user, f"Отредактирован пользователь: {username}")
                show_message("Успех", "Данные пользователя успешно обновлены.")

            self.update_user_list()
            dialog.destroy()
            if hasattr(self, 'admin_stats_label'):
                self.update_admin_stats_ui(self.stats_tab)

        ttk.Button(form_frame, text="Сохранить", command=save_user).grid(row=len(labels) + (1 if mode == "add" else 0),
                                                                         column=0, pady=15, padx=5)
        ttk.Button(form_frame, text="Отмена", command=dialog.destroy).grid(
            row=len(labels) + (1 if mode == "add" else 0), column=1, pady=15, padx=5)

    def toggle_user_status(self):
        selected_item = self.user_tree.selection()
        if not selected_item:
            show_message("Ошибка", "Пожалуйста, выберите пользователя для изменения статуса.", is_error=True)
            return

        username = selected_item[0]
        if username == current_user:
            show_message("Ошибка", "Вы не можете заблокировать или разблокировать свою собственную учетную запись.",
                         is_error=True)
            return

        user_data = users.get(username)
        if user_data:
            new_status = 'active' if user_data['status'] == 'blocked' else 'blocked'
            confirm_message = f"Вы уверены, что хотите {('разблокировать' if new_status == 'active' else 'заблокировать')} пользователя {username}?"
            if messagebox.askyesno("Подтверждение", confirm_message):
                users[username]['status'] = new_status
                log_action('admin_action', current_user, f"Статус пользователя '{username}' изменен на '{new_status}'")
                show_message("Успех", f"Статус пользователя '{username}' изменен на '{new_status}'.")
                self.update_user_list()
                if hasattr(self, 'admin_stats_label'):
                    self.update_admin_stats_ui(self.stats_tab)
        else:
            show_message("Ошибка", "Пользователь не найден.", is_error=True)

    def delete_user(self):
        selected_item = self.user_tree.selection()
        if not selected_item:
            show_message("Ошибка", "Пожалуйста, выберите пользователя для удаления.", is_error=True)
            return

        username = selected_item[0]
        if username == current_user:
            show_message("Ошибка", "Вы не можете удалить свою собственную учетную запись.", is_error=True)
            return

        confirm_message = f"Вы уверены, что хотите удалить пользователя {username}? Это действие необратимо."
        if messagebox.askyesno("Подтверждение удаления", confirm_message):
            if username in users:
                del users[username]
                log_action('admin_action', current_user, f"Удален пользователь: {username}")
                show_message("Успех", f"Пользователь '{username}' успешно удален.")
                self.update_user_list()
                if hasattr(self, 'admin_stats_label'):
                    self.update_admin_stats_ui(self.stats_tab)
            else:
                show_message("Ошибка", "Пользователь не найден.", is_error=True)

    def create_view_logs_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Журнал действий системы", font=('Inter', 14, 'bold')).pack(pady=10)

        self.log_tree = ttk.Treeview(parent_frame, columns=("Timestamp", "Type", "User", "Details"), show="headings")
        self.log_tree.heading("Timestamp", text="Время")
        self.log_tree.heading("Type", text="Тип")
        self.log_tree.heading("User", text="Пользователь")
        self.log_tree.heading("Details", text="Детали")

        self.log_tree.column("Timestamp", width=150, anchor=tk.W)
        self.log_tree.column("Type", width=100, anchor=tk.W)
        self.log_tree.column("User", width=100, anchor=tk.W)
        self.log_tree.column("Details", width=300, anchor=tk.W)

        self.log_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.log_tree.config(yscrollcommand=scrollbar.set)

        self.update_log_list()

    def update_log_list(self):
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)

        for log_entry in reversed(logs):
            self.log_tree.insert("", tk.END, values=(
                log_entry['timestamp'],
                log_entry['type'],
                log_entry['username'],
                log_entry['details']
            ))
        if hasattr(self, 'admin_stats_label'):
            self.update_admin_stats_ui(self.stats_tab)
        if hasattr(self, 'alerts_tree'):
            self.update_system_alerts_list()
        if hasattr(self, 'user_activity_tree'):
            self.update_user_activity_list(self.user_activity_selected_user.get())

    def create_admin_stats_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Статистика системы", font=('Inter', 14, 'bold')).pack(pady=10)

        self.admin_stats_label = ttk.Label(parent_frame, text="", font=('Inter', 12))
        self.admin_stats_label.pack(pady=10, anchor='w')
        self.update_admin_stats_ui(parent_frame)

        ttk.Button(parent_frame, text="Обновить статистику",
                   command=lambda: self.update_admin_stats_ui(parent_frame)).pack(pady=10)

    def update_admin_stats_ui(self, parent_frame):
        total_users = len(users)
        active_users = sum(1 for data in users.values() if data['status'] == 'active')
        blocked_users = total_users - active_users
        total_logins = sum(1 for log_entry in logs if log_entry['type'] == 'login_success')
        failed_logins = sum(
            1 for log_entry in logs if log_entry['type'] == 'login_attempt' and "Неверный" in log_entry['details'])

        stats_text = (
            f"Всего пользователей: {total_users}\n"
            f"Активных пользователей: {active_users}\n"
            f"Заблокированных пользователей: {blocked_users}\n\n"
            f"Успешных входов: {total_logins}\n"
            f"Неудачных попыток входа: {failed_logins}"
        )
        self.admin_stats_label.config(text=stats_text)

    def create_admin_settings_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Настройки системы", font=('Inter', 14, 'bold')).pack(pady=10)

        ttk.Checkbutton(parent_frame, text="Включить многофакторную аутентификацию (MFA)",
                        variable=self.mfa_enabled, onvalue=True, offvalue=False,
                        command=self.toggle_mfa_setting).pack(pady=10, anchor='w')

        ttk.Label(parent_frame, text="Здесь будут расположены другие настройки системы (например, правила паролей).",
                  wraplength=400).pack(pady=20)
        ttk.Button(parent_frame, text="Сохранить настройки (заглушка)", command=lambda: show_message("Настройки",
                                                                                                     "Функционал сохранения настроек пока не реализован.")).pack(
            pady=10)

    def toggle_mfa_setting(self):
        status = "включена" if self.mfa_enabled.get() else "отключена"
        log_action('admin_action', current_user, f"Многофакторная аутентификация {status}.")
        show_message("Настройка MFA", f"Многофакторная аутентификация теперь {status}.")

    def create_manage_roles_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Управление ролями", font=('Inter', 14, 'bold')).pack(pady=10)

        button_frame = ttk.Frame(parent_frame)
        button_frame.pack(pady=10, fill=tk.X)
        ttk.Button(button_frame, text="Добавить роль", command=self.add_role).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Редактировать роль", command=self.edit_role).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Удалить роль", command=self.delete_role).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Обновить список", command=self.update_roles_list).pack(side=tk.RIGHT, padx=5)

        self.roles_tree = ttk.Treeview(parent_frame, columns=("Role Name", "Permissions"), show="headings")
        self.roles_tree.heading("Role Name", text="Название роли")
        self.roles_tree.heading("Permissions", text="Разрешения")
        self.roles_tree.column("Role Name", width=150, anchor=tk.W)
        self.roles_tree.column("Permissions", width=400, anchor=tk.W)
        self.roles_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.roles_tree.yview)
        self.roles_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.roles_tree.config(yscrollcommand=scrollbar.set)

        self.update_roles_list()

    def update_roles_list(self):
        for item in self.roles_tree.get_children():
            self.roles_tree.delete(item)
        for role_name, permissions in roles_data.items():
            self.roles_tree.insert("", tk.END, iid=role_name, values=(role_name, ", ".join(permissions)))

    def add_role(self):
        self.create_add_edit_role_dialog("add")

    def edit_role(self):
        selected_item = self.roles_tree.selection()
        if not selected_item:
            show_message("Ошибка", "Пожалуйста, выберите роль для редактирования.", is_error=True)
            return
        role_name = selected_item[0]
        self.create_add_edit_role_dialog("edit", role_name)

    def create_add_edit_role_dialog(self, mode, role_name=None):
        dialog = tk.Toplevel(self.master)
        dialog.title("Добавить роль" if mode == "add" else "Редактировать роль")
        dialog.transient(self.master)
        dialog.grab_set()
        dialog.configure(bg='#3c3c3c')

        form_frame = ttk.Frame(dialog, padding="20 20 20 20")
        form_frame.pack()

        ttk.Label(form_frame, text="Название роли:").grid(row=0, column=0, sticky='w', pady=5, padx=5)
        role_name_entry = ttk.Entry(form_frame, width=30, font=('Inter', 12))
        role_name_entry.grid(row=0, column=1, pady=5, padx=5)

        ttk.Label(form_frame, text="Разрешения (через запятую):").grid(row=1, column=0, sticky='w', pady=5, padx=5)
        permissions_entry = ttk.Entry(form_frame, width=30, font=('Inter', 12))
        permissions_entry.grid(row=1, column=1, pady=5, padx=5)

        if mode == "edit" and role_name:
            role_name_entry.insert(0, role_name)
            role_name_entry.config(state='readonly')
            permissions_entry.insert(0, ", ".join(roles_data.get(role_name, [])))

        def save_role():
            new_role_name = role_name_entry.get().strip()
            new_permissions = [p.strip() for p in permissions_entry.get().split(',') if p.strip()]

            if not new_role_name:
                show_message("Ошибка", "Название роли не может быть пустым.", is_error=True)
                return

            if mode == "add":
                if new_role_name in roles_data:
                    show_message("Ошибка", "Роль с таким названием уже существует.", is_error=True)
                    return
                roles_data[new_role_name] = new_permissions
                log_action('admin_action', current_user,
                           f"Добавлена роль: {new_role_name} с разрешениями: {', '.join(new_permissions)}")
                show_message("Успех", "Роль успешно добавлена.")
            elif mode == "edit":
                if role_name not in roles_data:
                    show_message("Ошибка", "Редактируемая роль не найдена.", is_error=True)
                    return
                roles_data[role_name] = new_permissions
                log_action('admin_action', current_user,
                           f"Отредактирована роль: {role_name}, новые разрешения: {', '.join(new_permissions)}")
                show_message("Успех", "Роль успешно обновлена.")

            self.update_roles_list()
            dialog.destroy()
            self.update_user_list()

        ttk.Button(form_frame, text="Сохранить", command=save_role).grid(row=2, column=0, pady=15, padx=5)
        ttk.Button(form_frame, text="Отмена", command=dialog.destroy).grid(row=2, column=1, pady=15, padx=5)

    def delete_role(self):
        selected_item = self.roles_tree.selection()
        if not selected_item:
            show_message("Ошибка", "Пожалуйста, выберите роль для удаления.", is_error=True)
            return

        role_to_delete = selected_item[0]
        if role_to_delete in ['user', 'admin']:
            show_message("Ошибка", f"Системную роль '{role_to_delete}' удалить нельзя.", is_error=True)
            return

        users_with_role = [u for u_name, u_data in users.items() if u_data['role'] == role_to_delete]
        if users_with_role:
            show_message("Ошибка",
                         f"Невозможно удалить роль '{role_to_delete}', так как к ней привязаны пользователи: {', '.join(users_with_role)}.",
                         is_error=True)
            return

        confirm_message = f"Вы уверены, что хотите удалить роль '{role_to_delete}'? Это действие необратимо."
        if messagebox.askyesno("Подтверждение удаления", confirm_message):
            if role_to_delete in roles_data:
                del roles_data[role_to_delete]
                log_action('admin_action', current_user, f"Удалена роль: {role_to_delete}")
                show_message("Успех", f"Роль '{role_to_delete}' успешно удалена.")
                self.update_roles_list()
                self.update_user_list()
            else:
                show_message("Ошибка", "Роль не найдена.", is_error=True)

    def create_system_alerts_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Системные оповещения", font=('Inter', 14, 'bold')).pack(pady=10)

        self.alerts_tree = ttk.Treeview(parent_frame, columns=("Timestamp", "Level", "Message"), show="headings")
        self.alerts_tree.heading("Timestamp", text="Время")
        self.alerts_tree.heading("Level", text="Уровень")
        self.alerts_tree.heading("Message", text="Сообщение")

        self.alerts_tree.column("Timestamp", width=150, anchor=tk.W)
        self.alerts_tree.column("Level", width=100, anchor=tk.CENTER)
        self.alerts_tree.column("Message", width=400, anchor=tk.W)

        self.alerts_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.alerts_tree.config(yscrollcommand=scrollbar.set)

        self.update_system_alerts_list()

        ttk.Button(parent_frame, text="Обновить оповещения", command=self.update_system_alerts_list).pack(pady=10)

    def update_system_alerts_list(self):
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)

        for alert_entry in reversed(system_alerts):
            self.alerts_tree.insert("", tk.END, values=(
                alert_entry['timestamp'],
                alert_entry['level'],
                alert_entry['message']
            ))

    def create_manage_announcements_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Управление публичными объявлениями", font=('Inter', 14, 'bold')).pack(pady=10)

        button_frame = ttk.Frame(parent_frame)
        button_frame.pack(pady=10, fill=tk.X)
        ttk.Button(button_frame, text="Добавить объявление", command=self.add_announcement).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Редактировать объявление", command=self.edit_announcement).pack(side=tk.LEFT,
                                                                                                       padx=5)
        ttk.Button(button_frame, text="Удалить объявление", command=self.delete_announcement).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Обновить список", command=self.update_public_announcements_list_admin).pack(
            side=tk.RIGHT, padx=5)

        self.announcements_admin_tree = ttk.Treeview(parent_frame, columns=("ID", "Title", "Date"), show="headings")
        self.announcements_admin_tree.heading("ID", text="ID")
        self.announcements_admin_tree.heading("Title", text="Заголовок")
        self.announcements_admin_tree.heading("Date", text="Дата")
        self.announcements_admin_tree.column("ID", width=50, anchor=tk.CENTER)
        self.announcements_admin_tree.column("Title", width=300, anchor=tk.W)
        self.announcements_admin_tree.column("Date", width=100, anchor=tk.W)
        self.announcements_admin_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.announcements_admin_tree.yview)
        self.announcements_admin_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.announcements_admin_tree.config(yscrollcommand=scrollbar.set)

        self.update_public_announcements_list_admin()

    def update_public_announcements_list_admin(self):
        for item in self.announcements_admin_tree.get_children():
            self.announcements_admin_tree.delete(item)
        for announcement in public_announcements:
            self.announcements_admin_tree.insert("", tk.END, iid=announcement['id'], values=(
                announcement['id'],
                announcement['title'],
                announcement['date']
            ))
        if hasattr(self, 'announcements_tree'):
            self.update_public_announcements_list()

    def add_announcement(self):
        self.create_add_edit_announcement_dialog("add")

    def edit_announcement(self):
        selected_item = self.announcements_admin_tree.selection()
        if not selected_item:
            show_message("Ошибка", "Пожалуйста, выберите объявление для редактирования.", is_error=True)
            return
        announcement_id = int(selected_item[0])
        self.create_add_edit_announcement_dialog("edit", announcement_id)

    def create_add_edit_announcement_dialog(self, mode, announcement_id=None):
        dialog = tk.Toplevel(self.master)
        dialog.title("Добавить объявление" if mode == "add" else "Редактировать объявление")
        dialog.transient(self.master)
        dialog.grab_set()
        dialog.configure(bg='#3c3c3c')

        form_frame = ttk.Frame(dialog, padding="20 20 20 20")
        form_frame.pack()

        ttk.Label(form_frame, text="Заголовок:").grid(row=0, column=0, sticky='w', pady=5, padx=5)
        title_entry = ttk.Entry(form_frame, width=40, font=('Inter', 12))
        title_entry.grid(row=0, column=1, pady=5, padx=5)

        ttk.Label(form_frame, text="Дата (ГГГГ-ММ-ДД):").grid(row=1, column=0, sticky='w', pady=5, padx=5)
        date_entry = ttk.Entry(form_frame, width=40, font=('Inter', 12))
        date_entry.grid(row=1, column=1, pady=5, padx=5)
        date_entry.insert(0, datetime.date.today().strftime("%Y-%m-%d"))

        ttk.Label(form_frame, text="Содержание:").grid(row=2, column=0, sticky='w', pady=5, padx=5)
        content_text = tk.Text(form_frame, width=40, height=8, font=('Inter', 12),
                               bg='#5a5a5a', fg='#ffffff', insertbackground='#ffffff')
        content_text.grid(row=2, column=1, pady=5, padx=5)

        if mode == "edit" and announcement_id:
            announcement_data = next((a for a in public_announcements if a['id'] == announcement_id), None)
            if announcement_data:
                title_entry.insert(0, announcement_data['title'])
                date_entry.delete(0, tk.END)
                date_entry.insert(0, announcement_data['date'])
                content_text.insert(tk.END, announcement_data['content'])
            else:
                show_message("Ошибка", "Объявление не найдено.", is_error=True)
                dialog.destroy()
                return

        def save_announcement():
            new_title = title_entry.get().strip()
            new_date = date_entry.get().strip()
            new_content = content_text.get("1.0", tk.END).strip()

            if not new_title or not new_date or not new_content:
                show_message("Ошибка", "Пожалуйста, заполните все поля объявления.", is_error=True)
                return

            try:
                datetime.datetime.strptime(new_date, "%Y-%m-%d")
            except ValueError:
                show_message("Ошибка", "Неверный формат даты. Используйте ГГГГ-ММ-ДД.", is_error=True)
                return

            if mode == "add":
                new_id = max([a['id'] for a in public_announcements]) + 1 if public_announcements else 1
                public_announcements.append(
                    {'id': new_id, 'title': new_title, 'date': new_date, 'content': new_content})
                log_action('admin_action', current_user, f"Добавлено публичное объявление: '{new_title}'")
                show_message("Успех", "Объявление успешно добавлено.")
            elif mode == "edit":
                for i, ann in enumerate(public_announcements):
                    if ann['id'] == announcement_id:
                        public_announcements[i]['title'] = new_title
                        public_announcements[i]['date'] = new_date
                        public_announcements[i]['content'] = new_content
                        log_action('admin_action', current_user,
                                   f"Отредактировано публичное объявление: '{new_title}' (ID: {announcement_id})")
                        show_message("Успех", "Объявление успешно обновлено.")
                        break

            self.update_public_announcements_list_admin()
            dialog.destroy()

        ttk.Button(form_frame, text="Сохранить", command=save_announcement).grid(row=3, column=0, pady=15, padx=5)
        ttk.Button(form_frame, text="Отмена", command=dialog.destroy).grid(row=3, column=1, pady=15, padx=5)

    def delete_announcement(self):
        selected_item = self.announcements_admin_tree.selection()
        if not selected_item:
            show_message("Ошибка", "Пожалуйста, выберите объявление для удаления.", is_error=True)
            return

        announcement_id = int(selected_item[0])
        global public_announcements
        initial_len = len(public_announcements)
        public_announcements = [ann for ann in public_announcements if ann['id'] != announcement_id]

        if len(public_announcements) < initial_len:
            log_action('admin_action', current_user, f"Удалено публичное объявление с ID {announcement_id}.")
            show_message("Успех", "Объявление удалено.")
            self.update_public_announcements_list_admin()
        else:
            show_message("Ошибка", "Объявление не найдено.", is_error=True)

    def show_public_dashboard(self):
        self.public_dashboard_frame = ttk.Frame(self.master, padding="20 20 20 20")
        self.frames['public_dashboard'] = self.public_dashboard_frame

        ttk.Label(self.public_dashboard_frame, text="Публичный доступ", font=('Inter', 16, 'bold')).pack(pady=20)

        self.public_notebook = ttk.Notebook(self.public_dashboard_frame)
        self.public_notebook.pack(expand=True, fill=tk.BOTH, pady=10)

        self.public_announcements_tab = ttk.Frame(self.public_notebook, padding="10")
        self.public_news_tab = ttk.Frame(self.public_notebook, padding="10")
        self.public_careers_tab = ttk.Frame(self.public_notebook, padding="10")
        self.public_faq_tab = ttk.Frame(self.public_notebook, padding="10")
        self.public_contacts_tab = ttk.Frame(self.public_notebook, padding="10")

        self.public_notebook.add(self.public_announcements_tab, text="Объявления")
        self.public_notebook.add(self.public_news_tab, text="Новости")
        self.public_notebook.add(self.public_careers_tab, text="Вакансии")
        self.public_notebook.add(self.public_faq_tab, text="FAQ")
        self.public_notebook.add(self.public_contacts_tab, text="Контакты")

        self.create_public_announcements_ui(self.public_announcements_tab)
        self.create_public_news_ui(self.public_news_tab)
        self.create_public_careers_ui(self.public_careers_tab)
        self.create_public_faq_ui(self.public_faq_tab)
        self.create_public_contacts_ui(self.public_contacts_tab)

        ttk.Button(self.public_dashboard_frame, text="Вернуться к входу", command=self.go_to_login).pack(pady=20)
        self.show_frame('public_dashboard')

    def go_to_login(self):
        self.show_frame('login')

    def create_public_announcements_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Общедоступные объявления", font=('Inter', 14, 'bold')).pack(pady=10)

        self.announcements_tree = ttk.Treeview(parent_frame, columns=("Date", "Title", "Content"), show="headings")
        self.announcements_tree.heading("Date", text="Дата")
        self.announcements_tree.heading("Title", text="Заголовок")
        self.announcements_tree.heading("Content", text="Содержание")

        self.announcements_tree.column("Date", width=100, anchor=tk.W)
        self.announcements_tree.column("Title", width=200, anchor=tk.W)
        self.announcements_tree.column("Content", width=400, anchor=tk.W)

        self.announcements_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.announcements_tree.yview)
        self.announcements_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.announcements_tree.config(yscrollcommand=scrollbar.set)

        self.update_public_announcements_list()

    def update_public_announcements_list(self):
        for item in self.announcements_tree.get_children():
            self.announcements_tree.delete(item)

        for announcement in public_announcements:
            self.announcements_tree.insert("", tk.END, values=(
                announcement['date'],
                announcement['title'],
                announcement['content']
            ))

    def create_public_news_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Новости компании", font=('Inter', 14, 'bold')).pack(pady=10)

        self.news_tree = ttk.Treeview(parent_frame, columns=("Date", "Title", "Content"), show="headings")
        self.news_tree.heading("Date", text="Дата")
        self.news_tree.heading("Title", text="Заголовок")
        self.news_tree.heading("Content", text="Содержание")

        self.news_tree.column("Date", width=100, anchor=tk.W)
        self.news_tree.column("Title", width=200, anchor=tk.W)
        self.news_tree.column("Content", width=400, anchor=tk.W)

        self.news_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.news_tree.yview)
        self.news_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.news_tree.config(yscrollcommand=scrollbar.set)

        self.update_public_news_list()
        ttk.Button(parent_frame, text="Обновить новости", command=self.update_public_news_list).pack(pady=10)

    def update_public_news_list(self):
        for item in self.news_tree.get_children():
            self.news_tree.delete(item)

        for news_item in company_news_data:
            self.news_tree.insert("", tk.END, values=(
                news_item['date'],
                news_item['title'],
                news_item['content']
            ))

    def create_public_careers_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Открытые вакансии", font=('Inter', 14, 'bold')).pack(pady=10)

        self.careers_tree = ttk.Treeview(parent_frame, columns=("Title", "Department", "Location", "Status"),
                                         show="headings")
        self.careers_tree.heading("Title", text="Название вакансии")
        self.careers_tree.heading("Department", text="Отдел")
        self.careers_tree.heading("Location", text="Местоположение")
        self.careers_tree.heading("Status", text="Статус")

        self.careers_tree.column("Title", width=150, anchor=tk.W)
        self.careers_tree.column("Department", width=100, anchor=tk.W)
        self.careers_tree.column("Location", width=100, anchor=tk.W)
        self.careers_tree.column("Status", width=80, anchor=tk.CENTER)

        self.careers_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.careers_tree.yview)
        self.careers_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.careers_tree.config(yscrollcommand=scrollbar.set)

        self.update_job_openings_list()
        ttk.Button(parent_frame, text="Обновить вакансии", command=self.update_job_openings_list).pack(pady=10)

    def update_job_openings_list(self):
        for item in self.careers_tree.get_children():
            self.careers_tree.delete(item)

        for job in job_openings_data:
            self.careers_tree.insert("", tk.END, values=(
                job['title'],
                job['department'],
                job['location'],
                job['status']
            ))

    def create_public_contacts_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Контактная информация компании", font=('Inter', 14, 'bold')).pack(pady=10)
        ttk.Label(parent_frame, text="Основные контакты:", wraplength=500).pack(pady=10, anchor='w')
        ttk.Label(parent_frame, text="Главный офис: ул. Примерная, д. 10, Город N").pack(anchor='w', pady=2)
        ttk.Label(parent_frame, text="Телефон: +1 (800) 123-4567").pack(anchor='w', pady=2)
        ttk.Label(parent_frame, text="Email: info@company.com").pack(anchor='w', pady=2)
        ttk.Label(parent_frame, text="\nСлужба поддержки:", wraplength=500).pack(pady=10, anchor='w')
        ttk.Label(parent_frame, text="Email: support@company.com").pack(anchor='w', pady=2)
        ttk.Label(parent_frame, text="Телефон: +1 (800) 987-6543").pack(anchor='w', pady=2)
        ttk.Label(parent_frame, text="Часы работы: Пн-Пт, 9:00 - 18:00").pack(anchor='w', pady=2)

    def create_public_faq_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Часто задаваемые вопросы (FAQ)", font=('Inter', 14, 'bold')).pack(pady=10)

        self.faq_tree = ttk.Treeview(parent_frame, columns=("Question", "Answer"), show="headings")
        self.faq_tree.heading("Question", text="Вопрос")
        self.faq_tree.heading("Answer", text="Ответ")

        self.faq_tree.column("Question", width=250, anchor=tk.W)
        self.faq_tree.column("Answer", width=450, anchor=tk.W)

        self.faq_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.faq_tree.yview)
        self.faq_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.faq_tree.config(yscrollcommand=scrollbar.set)

        self.update_public_faq_list()
        ttk.Button(parent_frame, text="Обновить FAQ", command=self.update_public_faq_list).pack(pady=10)

    def update_public_faq_list(self):
        for item in self.faq_tree.get_children():
            self.faq_tree.delete(item)

        for faq in public_faq_data:
            self.faq_tree.insert("", tk.END, values=(faq['question'], faq['answer']))

    def create_user_activity_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Активность пользователя", font=('Inter', 14, 'bold')).pack(pady=10)

        user_selection_frame = ttk.Frame(parent_frame)
        user_selection_frame.pack(pady=10, fill=tk.X)

        ttk.Label(user_selection_frame, text="Выберите пользователя:").pack(side=tk.LEFT, padx=5)
        self.user_activity_selected_user = tk.StringVar()
        self.user_activity_user_select = ttk.Combobox(user_selection_frame,
                                                      textvariable=self.user_activity_selected_user,
                                                      values=list(users.keys()), state="readonly", width=20)
        self.user_activity_user_select.pack(side=tk.LEFT, padx=5)
        self.user_activity_user_select.set("admin")
        self.user_activity_user_select.bind("<<ComboboxSelected>>", lambda event: self.update_user_activity_list(
            self.user_activity_selected_user.get()))

        ttk.Button(user_selection_frame, text="Обновить активность",
                   command=lambda: self.update_user_activity_list(self.user_activity_selected_user.get())).pack(
            side=tk.LEFT, padx=10)

        self.user_activity_tree = ttk.Treeview(parent_frame, columns=("Timestamp", "Type", "Details"), show="headings")
        self.user_activity_tree.heading("Timestamp", text="Время")
        self.user_activity_tree.heading("Type", text="Тип")
        self.user_activity_tree.heading("Details", text="Детали")

        self.user_activity_tree.column("Timestamp", width=150, anchor=tk.W)
        self.user_activity_tree.column("Type", width=100, anchor=tk.W)
        self.user_activity_tree.column("Details", width=400, anchor=tk.W)

        self.user_activity_tree.pack(fill=tk.BOTH, expand=True, pady=10)

        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=self.user_activity_tree.yview)
        self.user_activity_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.user_activity_tree.config(yscrollcommand=scrollbar.set)

        self.update_user_activity_list(self.user_activity_selected_user.get())

    def update_user_activity_list(self, username_filter):
        for item in self.user_activity_tree.get_children():
            self.user_activity_tree.delete(item)

        filtered_logs = [log_entry for log_entry in logs if log_entry['username'] == username_filter]
        for log_entry in reversed(filtered_logs):
            self.user_activity_tree.insert("", tk.END, values=(
                log_entry['timestamp'],
                log_entry['type'],
                log_entry['details']
            ))

    def create_admin_system_config_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Продвинутая конфигурация системы", font=('Inter', 14, 'bold')).pack(pady=10)
        ttk.Label(parent_frame,
                  text="Здесь можно будет настроить политики паролей, время жизни сессий, интеграции и т.д.",
                  wraplength=500).pack(pady=20)

        ttk.Label(parent_frame, text="Минимальная длина пароля:").pack(anchor='w', pady=5)
        ttk.Entry(parent_frame, width=10, font=('Inter', 12)).insert(0, "8")
        ttk.Entry(parent_frame, width=10, font=('Inter', 12)).pack(anchor='w', padx=5)

        ttk.Button(parent_frame, text="Сохранить конфигурацию (заглушка)", command=lambda: show_message("Конфигурация",
                                                                                                        "Функционал сохранения конфигурации пока не реализован.")).pack(
            pady=10)

    def create_admin_reports_ui(self, parent_frame):
        ttk.Label(parent_frame, text="Генерация отчетов", font=('Inter', 14, 'bold')).pack(pady=10)
        ttk.Label(parent_frame, text="Выберите тип отчета для генерации:", wraplength=500).pack(pady=10)

        ttk.Button(parent_frame, text="Отчет по входам в систему",
                   command=lambda: show_message("Отчет", "Отчет по входам сгенерирован (имитация).")).pack(pady=5)
        ttk.Button(parent_frame, text="Отчет по ролям пользователей",
                   command=lambda: show_message("Отчет", "Отчет по ролям сгенерирован (имитация).")).pack(pady=5)
        ttk.Button(parent_frame, text="Отчет по заблокированным аккаунтам", command=lambda: show_message("Отчет",
                                                                                                         "Отчет по заблокированным аккаунтам сгенерирован (имитация).")).pack(
            pady=5)
        ttk.Button(parent_frame, text="Отчет по заявкам на отпуск",
                   command=lambda: show_message("Отчет", "Отчет по заявкам на отпуск сгенерирован (имитация).")).pack(
            pady=5)


if __name__ == "__main__":
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()
