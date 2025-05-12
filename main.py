import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import logging
from datetime import datetime

from password_generator import generate_password
from password_analyzer import analyze_password, analyze_password_file
from password_statistics import log_generation, log_analysis, get_statistics, visualize_statistics
from file_encryption import encrypt_file, decrypt_file, generate_key, save_key, load_key

# Configure logging
logging.basicConfig(
    filename=f'password_app_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Генератор и Анализатор Паролей")
        self.root.geometry("800x600")
        
        # Create tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tab frames
        self.generator_tab = ttk.Frame(self.notebook)
        self.analyzer_tab = ttk.Frame(self.notebook)
        self.file_analyzer_tab = ttk.Frame(self.notebook)
        self.statistics_tab = ttk.Frame(self.notebook)
        self.encryption_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.generator_tab, text="Генератор Паролей")
        self.notebook.add(self.analyzer_tab, text="Анализатор Паролей")
        self.notebook.add(self.file_analyzer_tab, text="Анализ Файла")
        self.notebook.add(self.statistics_tab, text="Статистика")
        self.notebook.add(self.encryption_tab, text="Шифрование")
        
        # Setup tabs
        self._setup_generator_tab()
        self._setup_analyzer_tab()
        self._setup_file_analyzer_tab()
        self._setup_statistics_tab()
        self._setup_encryption_tab()
        
        logging.info("Application started")

    def _setup_generator_tab(self):
        # Длина пароля
        ttk.Label(self.generator_tab, text="Длина пароля:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.length_var = tk.IntVar(value=12)
        ttk.Spinbox(self.generator_tab, from_=8, to=64, textvariable=self.length_var, width=5).grid(row=0, column=1, padx=10, pady=10, sticky="w")
        
        # Фрейм опций
        options_frame = ttk.LabelFrame(self.generator_tab, text="Опции")
        options_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        
        # Чекбоксы для опций
        self.uppercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Включить заглавные буквы", variable=self.uppercase_var).grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        self.lowercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Включить строчные буквы", variable=self.lowercase_var).grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        self.digits_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Включить цифры", variable=self.digits_var).grid(row=2, column=0, padx=10, pady=5, sticky="w")
        
        self.symbols_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Включить специальные символы", variable=self.symbols_var).grid(row=3, column=0, padx=10, pady=5, sticky="w")
        
        # Кнопка генерации
        ttk.Button(self.generator_tab, text="Сгенерировать пароль", command=self._generate_password).grid(row=2, column=0, columnspan=2, padx=10, pady=10)
        
        # Результат
        ttk.Label(self.generator_tab, text="Сгенерированный пароль:").grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(self.generator_tab, textvariable=self.password_var, width=40)
        password_entry.grid(row=3, column=1, padx=10, pady=10, sticky="w")
        
        # Кнопка копирования
        ttk.Button(self.generator_tab, text="Копировать в буфер обмена", command=self._copy_to_clipboard).grid(row=4, column=0, columnspan=2, padx=10, pady=10)

    def _setup_analyzer_tab(self):
        ttk.Label(self.analyzer_tab, text="Введите пароль для анализа:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.analyze_password_var = tk.StringVar()
        ttk.Entry(self.analyzer_tab, textvariable=self.analyze_password_var, width=40).grid(row=0, column=1, padx=10, pady=10, sticky="w")
        
        ttk.Button(self.analyzer_tab, text="Анализировать пароль", command=self._analyze_password).grid(row=1, column=0, columnspan=2, padx=10, pady=10)
        
        # Фрейм результатов
        results_frame = ttk.LabelFrame(self.analyzer_tab, text="Результаты анализа")
        results_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        
        ttk.Label(results_frame, text="Надежность:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.strength_var = tk.StringVar()
        ttk.Label(results_frame, textvariable=self.strength_var).grid(row=0, column=1, padx=10, pady=5, sticky="w")
        
        ttk.Label(results_frame, text="Детали:").grid(row=1, column=0, padx=10, pady=5, sticky="nw")
        self.details_text = tk.Text(results_frame, width=50, height=10, wrap=tk.WORD)
        self.details_text.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")
        self.details_text.config(state=tk.DISABLED)

    def _setup_file_analyzer_tab(self):
        ttk.Label(self.file_analyzer_tab, text="Выберите файл с паролями (по одному на строку):").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.file_path_var = tk.StringVar()
        ttk.Entry(self.file_analyzer_tab, textvariable=self.file_path_var, width=40).grid(row=0, column=1, padx=10, pady=10, sticky="w")
        ttk.Button(self.file_analyzer_tab, text="Обзор...", command=self._browse_file).grid(row=0, column=2, padx=10, pady=10)
        
        ttk.Button(self.file_analyzer_tab, text="Анализировать файл", command=self._analyze_file).grid(row=1, column=0, columnspan=3, padx=10, pady=10)
        
        # Результаты
        self.file_results_text = tk.Text(self.file_analyzer_tab, width=70, height=20, wrap=tk.WORD)
        self.file_results_text.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
        self.file_results_text.config(state=tk.DISABLED)
        
        # Создание полосы прокрутки
        scrollbar = ttk.Scrollbar(self.file_analyzer_tab, command=self.file_results_text.yview)
        scrollbar.grid(row=2, column=3, sticky="ns")
        self.file_results_text.config(yscrollcommand=scrollbar.set)
        
        # Настройка расширяемости текстовой области
        self.file_analyzer_tab.columnconfigure(0, weight=1)
        self.file_analyzer_tab.rowconfigure(2, weight=1)

    def _setup_statistics_tab(self):
        ttk.Button(self.statistics_tab, text="Загрузить статистику", command=self._load_statistics).grid(row=0, column=0, padx=10, pady=10)
        ttk.Button(self.statistics_tab, text="Визуализировать данные", command=self._visualize_statistics).grid(row=0, column=1, padx=10, pady=10)
        
        self.stats_text = tk.Text(self.statistics_tab, width=70, height=20, wrap=tk.WORD)
        self.stats_text.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.stats_text.config(state=tk.DISABLED)
        
        # Создание полосы прокрутки
        scrollbar = ttk.Scrollbar(self.statistics_tab, command=self.stats_text.yview)
        scrollbar.grid(row=1, column=2, sticky="ns")
        self.stats_text.config(yscrollcommand=scrollbar.set)
        
        # Настройка расширяемости текстовой области
        self.statistics_tab.columnconfigure(0, weight=1)
        self.statistics_tab.rowconfigure(1, weight=1)

    def _setup_encryption_tab(self):
        # Фрейм для шифрования файла
        encrypt_frame = ttk.LabelFrame(self.encryption_tab, text="Шифрование файла")
        encrypt_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Выбор файла для шифрования
        ttk.Label(encrypt_frame, text="Файл для шифрования:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.encrypt_file_path = tk.StringVar()
        ttk.Entry(encrypt_frame, textvariable=self.encrypt_file_path, width=40).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(encrypt_frame, text="Обзор...", command=lambda: self._browse_encrypt_file()).grid(row=0, column=2, padx=5, pady=5)
        
        # Пароль для шифрования
        ttk.Label(encrypt_frame, text="Пароль для шифрования:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.encrypt_password = tk.StringVar()
        ttk.Entry(encrypt_frame, textvariable=self.encrypt_password, show="*", width=40).grid(row=1, column=1, padx=5, pady=5)
        
        # Кнопка шифрования
        ttk.Button(encrypt_frame, text="Зашифровать файл", command=self._encrypt_file).grid(row=2, column=0, columnspan=3, pady=10)
        
        # Фрейм для расшифровки файла
        decrypt_frame = ttk.LabelFrame(self.encryption_tab, text="Расшифровка файла")
        decrypt_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
        # Выбор файла для расшифровки
        ttk.Label(decrypt_frame, text="Зашифрованный файл:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.decrypt_file_path = tk.StringVar()
        ttk.Entry(decrypt_frame, textvariable=self.decrypt_file_path, width=40).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(decrypt_frame, text="Обзор...", command=lambda: self._browse_decrypt_file()).grid(row=0, column=2, padx=5, pady=5)
        
        # Пароль для расшифровки
        ttk.Label(decrypt_frame, text="Пароль для расшифровки:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.decrypt_password = tk.StringVar()
        ttk.Entry(decrypt_frame, textvariable=self.decrypt_password, show="*", width=40).grid(row=1, column=1, padx=5, pady=5)
        
        # Кнопка расшифровки
        ttk.Button(decrypt_frame, text="Расшифровать файл", command=self._decrypt_file).grid(row=2, column=0, columnspan=3, pady=10)
        
        # Настройка расширяемости
        self.encryption_tab.columnconfigure(0, weight=1)
        self.encryption_tab.rowconfigure(0, weight=1)
        self.encryption_tab.rowconfigure(1, weight=1)

    def _generate_password(self):
        try:
            length = self.length_var.get()
            options = {
                'uppercase': self.uppercase_var.get(),
                'lowercase': self.lowercase_var.get(),
                'digits': self.digits_var.get(),
                'symbols': self.symbols_var.get()
            }
            
            password = generate_password(length, **options)
            self.password_var.set(password)
            log_generation(password)
            logging.info(f"Generated password with length {length}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать пароль: {str(e)}")
            logging.error(f"Error generating password: {str(e)}")

    def _copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Успех", "Пароль скопирован в буфер обмена!")
            logging.info("Пароль скопирован в буфер обмена")

    def _analyze_password(self):
        password = self.analyze_password_var.get()
        if not password:
            messagebox.showwarning("Предупреждение", "Пожалуйста, введите пароль для анализа.")
            return
        
        try:
            result = analyze_password(password)
            self.strength_var.set(result["strength"])
            
            self.details_text.config(state=tk.NORMAL)
            self.details_text.delete(1.0, tk.END)
            for key, value in result["details"].items():
                self.details_text.insert(tk.END, f"{key}: {value}\n")
            self.details_text.config(state=tk.DISABLED)
            
            log_analysis(password, result["strength"])
            logging.info(f"Password analyzed with strength: {result['strength']}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось проанализировать пароль: {str(e)}")
            logging.error(f"Error analyzing password: {str(e)}")

    def _browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")])
        if file_path:
            self.file_path_var.set(file_path)

    def _analyze_file(self):
        file_path = self.file_path_var.get()
        if not file_path:
            messagebox.showwarning("Предупреждение", "Пожалуйста, выберите файл.")
            return
        
        try:
            results = analyze_password_file(file_path)
            
            self.file_results_text.config(state=tk.NORMAL)
            self.file_results_text.delete(1.0, tk.END)
            
            self.file_results_text.insert(tk.END, f"Анализ файла {file_path}\n")
            self.file_results_text.insert(tk.END, f"Всего проанализировано паролей: {results['total']}\n")
            self.file_results_text.insert(tk.END, f"Надежных паролей: {results['strong']}\n")
            self.file_results_text.insert(tk.END, f"Средних паролей: {results['medium']}\n")
            self.file_results_text.insert(tk.END, f"Слабых паролей: {results['weak']}\n\n")
            self.file_results_text.insert(tk.END, "Детальные результаты:\n")
            
            for password, result in results["details"].items():
                self.file_results_text.insert(tk.END, f"\nПароль: {password}\n")
                self.file_results_text.insert(tk.END, f"Надежность: {result['strength']}\n")
                for key, value in result['details'].items():
                    self.file_results_text.insert(tk.END, f"{key}: {value}\n")
            
            self.file_results_text.config(state=tk.DISABLED)
            logging.info(f"File analyzed: {file_path}, processed {results['total']} passwords")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось проанализировать файл: {str(e)}")
            logging.error(f"Error analyzing file {file_path}: {str(e)}")

    def _load_statistics(self):
        try:
            stats = get_statistics()
            
            self.stats_text.config(state=tk.NORMAL)
            self.stats_text.delete(1.0, tk.END)
            
            self.stats_text.insert(tk.END, "Статистика паролей:\n\n")
            self.stats_text.insert(tk.END, f"Всего сгенерировано паролей: {stats['generated']}\n")
            self.stats_text.insert(tk.END, f"Всего проанализировано паролей: {stats['analyzed']}\n\n")
            self.stats_text.insert(tk.END, "Распределение по надежности:\n")
            self.stats_text.insert(tk.END, f"Надежных паролей: {stats['strength']['strong']}\n")
            self.stats_text.insert(tk.END, f"Средних паролей: {stats['strength']['medium']}\n")
            self.stats_text.insert(tk.END, f"Слабых паролей: {stats['strength']['weak']}\n")
            
            self.stats_text.config(state=tk.DISABLED)
            logging.info("Statistics loaded")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить статистику: {str(e)}")
            logging.error(f"Error loading statistics: {str(e)}")

    def _visualize_statistics(self):
        try:
            visualize_statistics()
            logging.info("Statistics visualization completed")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось визуализировать статистику: {str(e)}")
            logging.error(f"Error visualizing statistics: {str(e)}")

    def _browse_encrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Все файлы", "*.*")])
        if file_path:
            self.encrypt_file_path.set(file_path)

    def _browse_decrypt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Зашифрованные файлы", "*.encrypted"), ("Все файлы", "*.*")])
        if file_path:
            self.decrypt_file_path.set(file_path)

    def _encrypt_file(self):
        source_path = self.encrypt_file_path.get()
        password = self.encrypt_password.get()
        
        if not source_path:
            messagebox.showwarning("Предупреждение", "Выберите файл для шифрования")
            return
        
        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль для шифрования")
            return
        
        try:
            target_path = source_path + ".encrypted"
            if encrypt_file(source_path, target_path, password):
                messagebox.showinfo("Успех", f"Файл успешно зашифрован и сохранен как:\n{target_path}")
                logging.info(f"File encrypted: {source_path} -> {target_path}")
            else:
                messagebox.showerror("Ошибка", "Не удалось зашифровать файл")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при шифровании: {str(e)}")
            logging.error(f"Error encrypting file {source_path}: {str(e)}")

    def _decrypt_file(self):
        source_path = self.decrypt_file_path.get()
        password = self.decrypt_password.get()
        
        if not source_path:
            messagebox.showwarning("Предупреждение", "Выберите файл для расшифровки")
            return
        
        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль для расшифровки")
            return
        
        try:
            target_path = source_path.replace(".encrypted", ".decrypted")
            if decrypt_file(source_path, target_path, password):
                messagebox.showinfo("Успех", f"Файл успешно расшифрован и сохранен как:\n{target_path}")
                logging.info(f"File decrypted: {source_path} -> {target_path}")
            else:
                messagebox.showerror("Ошибка", "Не удалось расшифровать файл")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при расшифровке: {str(e)}")
            logging.error(f"Error decrypting file {source_path}: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordApp(root)
    root.mainloop() 