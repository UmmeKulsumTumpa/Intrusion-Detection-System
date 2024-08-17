import tkinter as tk
from tkinter import filedialog, ttk
import pandas as pd
import os
from joblib import load
import sys
from sklearn.linear_model import _logistic
from sklearn import tree
from sklearn.preprocessing import _data
sys.modules['sklearn.linear_model.logistic'] = _logistic
sys.modules['sklearn.tree.tree'] = tree
sys.modules['sklearn.preprocessing.data'] = _data

class IntrusionDetectionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Intrusion Detection")
        self.geometry("800x600")
        self.tree = None  # Initialize self.tree
        self.scrollbar = None  # Initialize scrollbar
        self.create_main_menu()

    def create_main_menu(self):
        # Title Frame with Excellent Font
        title_frame = tk.Frame(self, bg="light sky blue", height=120)
        title_frame.pack(fill="x")

        title_label = tk.Label(title_frame, text="Intrusion Detection System", font=("Segoe UI Bold", 30, "bold"),
                               fg="black", bg="light sky blue")
        title_label.place(relx=0.5, rely=0.5, anchor="center")

        # Live Detection Button
        live_detection_button = tk.Button(self, text="< Live Detection >", font=("Segoe UI", 14, "bold"), bg="#d9d9d9",
                                          fg="black", bd=2, cursor="hand2", relief="raised",
                                          command=self.live_detection,
                                          padx=20, pady=10, width=15)
        live_detection_button.pack(side="top", pady=20)
        live_detection_button.bind("<Enter>",
                                   lambda event, btn=live_detection_button: btn.config(bg="#b3b3b3", fg="black"))
        live_detection_button.bind("<Leave>",
                                   lambda event, btn=live_detection_button: btn.config(bg="#d9d9d9", fg="black"))

        # Use File Button
        use_file_button = tk.Button(self, text="< Use File >", font=("Segoe UI", 14, "bold"), bg="#d9d9d9", fg="black",
                                    bd=2,
                                    cursor="hand2", relief="raised", command=self.use_file,
                                    padx=20, pady=10, width=15)
        use_file_button.pack(side="top", pady=40)
        use_file_button.bind("<Enter>", lambda event, btn=use_file_button: btn.config(bg="#b3b3b3", fg="black"))
        use_file_button.bind("<Leave>", lambda event, btn=use_file_button: btn.config(bg="#d9d9d9", fg="black"))

        # Test Button
        test_button = tk.Button(self, text="< Test >", font=("Segoe UI", 14, "bold"), bg="#d9d9d9", fg="black",
                                bd=2, cursor="hand2", relief="raised",
                                command=self.test_function,  # Replace self.test_function with your actual test function
                                padx=20, pady=10, width=15)
        test_button.pack(side="top", pady=20)
        test_button.bind("<Enter>", lambda event, btn=test_button: btn.config(bg="#b3b3b3", fg="black"))
        test_button.bind("<Leave>", lambda event, btn=test_button: btn.config(bg="#d9d9d9", fg="black"))

    def live_detection(self):
        # Add live detection logic here
        pass

    def use_file(self):
        filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if filename:
            self.clear_main_menu()  # Clear the main menu before displaying CSV data
            self.display_csv_data(filename)

    def predict_attack(self):
        try:
            # Load the pre-trained models and scaler
            dtc_classifier = load(r'F:\Academic\intrusion-detection\resources\DTC_Classifier')
            selected_features = load(r'F:\Academic\intrusion-detection\resources\selected_features')
            scaler = load(r'F:\Academic\intrusion-detection\resources\std_scaler')

            # Read the dataset
            data = pd.read_csv(self.filename)  # Use raw string literal to avoid SyntaxWarning

            # Rename columns
            new_column_names = {
                'dst_port': 'Destination Port',
                'totlen_fwd_pkts': 'Total Length of Fwd Packets',
                'totlen_bwd_pkts': 'Total Length of Bwd Packets',
                'fwd_pkt_len_max': 'Fwd Packet Length Max',
                'bwd_pkt_len_mean': 'Bwd Packet Length Mean',
                'bwd_pkt_len_std': 'Bwd Packet Length Std',
                'flow_iat_mean': 'Flow IAT Mean',
                'flow_iat_max': 'Flow IAT Max',
                'fwd_iat_min': 'Fwd IAT Min',
                'fwd_header_len': 'Fwd Header Length',
                'bwd_header_len': 'Bwd Header Length',
                'fwd_pkts_s': 'Fwd Packets/s',
                'bwd_pkts_s': 'Bwd Packets/s',
                'pkt_len_mean': 'Packet Length Mean',
                'pkt_len_std': 'Packet Length Std',
                'pkt_len_var': 'Packet Length Variance',
                'pkt_size_avg': 'Average Packet Size',
                'bwd_seg_size_avg': 'Avg Bwd Segment Size',
                'subflow_fwd_byts': 'Subflow Fwd Bytes',
                'subflow_bwd_byts': 'Subflow Bwd Bytes',
                'init_fwd_win_byts': 'Init_Win_bytes_forward',
                'init_bwd_win_byts': 'Init_Win_bytes_backward'
            }
            data.rename(columns=new_column_names, inplace=True)

            # Remove all columns except selected_features
            selected_features_cleaned = [feature.strip() for feature in selected_features]
            selected_features_cleaned = [feature for feature in selected_features_cleaned if
                                         feature != 'Fwd Header Length.1']
            filtered_data = data[selected_features_cleaned]

            # Trim scaler mean and scale vectors to match the number of features
            scaler.mean_ = scaler.mean_[:filtered_data.shape[1]]
            scaler.scale_ = scaler.scale_[:filtered_data.shape[1]]

            # Transform the data
            sc_train = scaler.transform(filtered_data.select_dtypes(include=['float64', 'int64']))

            # Predict using the Decision Tree classifier
            pred_dt = dtc_classifier.predict(sc_train)

            # Add the predicted data as a new column
            filtered_data['Model Prediction'] = pred_dt

            # Reorder columns with "Model Prediction" as the first column
            cols = filtered_data.columns.tolist()
            cols = ['Model Prediction'] + [col for col in cols if col != 'Model Prediction']
            filtered_data = filtered_data[cols]

            return filtered_data

        except Exception as e:
            error_heading = "Please select a valid input file"
            error_message = f"An error occurred: {e}"

            error_frame = tk.Frame(self)
            error_frame.pack(fill="both", expand=True)

            heading_label = tk.Label(error_frame, text=error_heading, font=("Segoe UI", 20, "bold"), fg="red")
            heading_label.pack(pady=5)

            error_label = tk.Label(error_frame, text=error_message, font=("Segoe UI", 12), fg="red", wraplength=700)
            error_label.pack(pady=10)

            back_button = tk.Button(error_frame, text="Back to Main Menu", font=("Segoe UI", 14), relief="raised", command=self.back_to_main_menu)
            back_button.pack(pady=5)

            # Configure error frame to expand vertically to fit the error message
            error_frame.grid_rowconfigure(0, weight=1)

            return False, None  # Return False and None as data

    def display_csv_data(self, filename=None):
        if filename:
            self.filename = filename

        if not self.filename:
            return

        if self.tree:
            self.tree.destroy()

        if self.scrollbar:
            self.scrollbar.destroy()

        # Clear existing data
        self.data = None

        self.data = self.predict_attack()
        self.columns = self.data.columns.tolist()

        self.table_label = tk.Label(self, text="Displaying CSV Data", font=("Segoe UI Bold", 16, "bold"))
        self.table_label.pack(pady=10)

        self.back_button = tk.Button(self, text="Back", font=("Segoe UI", 12, "bold"), bg="#d9d9d9",
                                     fg="black", bd=2, cursor="hand2", relief="raised", command=self.back_to_main_menu)
        self.back_button.pack(side="top", anchor="nw", padx=3, pady=3)  # Pack button at the top left corner

        self.tree_frame = tk.Frame(self)
        self.tree_frame.pack(fill="both", expand=True)

        self.yscroll = tk.Scrollbar(self.tree_frame, orient="vertical")
        self.yscroll.pack(side="right", fill="y")

        self.xscroll = tk.Scrollbar(self.tree_frame, orient="horizontal")
        self.xscroll.pack(side="bottom", fill="x")

        self.tree = ttk.Treeview(self.tree_frame, columns=self.columns, show="headings",
                                 yscrollcommand=self.yscroll.set, xscrollcommand=self.xscroll.set)
        self.tree.pack(side="left", fill="both", expand=True)

        self.yscroll.config(command=self.tree.yview)
        self.xscroll.config(command=self.tree.xview)

        # Set style to change heading background color
        style = ttk.Style()
        style.map("Treeview.Heading", background=[("active", "lightblue")])

        for col in self.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")

        for index, row in self.data.iterrows():
            prediction = row["Model Prediction"]
            if prediction != 0:
                self.tree.insert("", "end", values=row.tolist(), tags=("red_row",))
            else:
                self.tree.insert("", "end", values=row.tolist())

        self.tree.tag_configure("red_row", background="light coral")

        self.tree.bind("<ButtonRelease-1>", self.on_click)

        # self.bind("<Enter>", lambda event, btn=self.back_button: btn.config(bg="#b3b3b3", fg="black"))
        # self.bind("<Leave>", lambda event, btn=self.back_button: btn.config(bg="#d9d9d9", fg="black"))

        if not hasattr(self, "check_changes"):
            self.check_changes = self.after(5000, self.check_for_changes)

        # Scroll to the bottom of the frame and select the last row
        self.tree.yview_moveto(1)
        self.tree.selection_set(self.tree.get_children()[-1])

    def check_for_changes(self):
        if self.filename:
            current_modified_time = os.path.getmtime(self.filename)
            if current_modified_time != getattr(self, "last_modified_time", None):
                self.last_modified_time = current_modified_time
                self.update_csv_data()
        self.check_changes = self.after(5000, self.check_for_changes)  # Check again after 5 seconds

    def update_csv_data(self):
        new_data = self.predict_attack()
        new_rows = new_data.shape[0] - self.data.shape[0]
        if new_rows > 0:
            new_rows_data = new_data.iloc[-new_rows:].values.tolist()
            for row in new_rows_data:
                # self.tree.insert("", "end", values=row)
                prediction = row[0]
                if prediction != 0:
                    self.tree.insert("", "end", values=row, tags=("red_row",))
                else:
                    self.tree.insert("", "end", values=row)

            self.tree.tag_configure("red_row", background="light coral")

            self.data = new_data
            self.tree.yview_moveto(1)  # Automatically scroll to the bottom
            self.tree.selection_set(self.tree.get_children()[-1])  # Select the last row

    def clear_main_menu(self):
        for widget in self.winfo_children():
            widget.destroy()

    def back_to_main_menu(self):
        self.clear_main_menu()
        self.create_main_menu()

    def on_click(self, event):
        item = self.tree.selection()[0]
        values = self.tree.item(item, "values")
        row_data = dict(zip(self.columns, values))  # Convert values to a dictionary
        self.show_panel(row_data)

    def show_panel(self, row_info):
        if hasattr(self, "panel_panedwindow"):
            self.panel_panedwindow.destroy()

        self.panel_panedwindow = tk.PanedWindow(self, orient="vertical", sashrelief="sunken")
        self.panel_panedwindow.pack(side="bottom", fill="both", expand=True)

        # Title for panel
        panel_title = tk.Label(self.panel_panedwindow, text="Detailed Info", font=("Segoe UI Bold", 16, "bold"))
        panel_title.pack(side="top", pady=5)

        # Create a border for the panel
        panel_frame = tk.Frame(self.panel_panedwindow, bd=2, relief="ridge")
        panel_frame.pack(side="top", fill="both", expand=True)

        # Close button
        close_button = tk.Button(panel_frame, text="X", command=self.close_panel, bg="red", fg="black", width=2)
        close_button.pack(anchor="nw", padx=3, pady=3)

        info_str = "\n".join([f"{column}: {value}" for column, value in row_info.items()])

        # Split data into two columns
        half_length = len(row_info) // 2
        left_info = {k: v for i, (k, v) in enumerate(row_info.items()) if i < half_length}
        right_info = {k: v for i, (k, v) in enumerate(row_info.items()) if i >= half_length}

        info_frame = tk.Frame(panel_frame)
        info_frame.pack(side="top", fill="both", expand=True)

        left_column_label = tk.Label(info_frame,
                                     text="\n".join([f"{column}: {value}" for column, value in left_info.items()]),
                                     anchor="nw", justify="left", font=("Helvetica", 10))
        left_column_label.pack(side="left", fill="both", expand=True)

        right_column_label = tk.Label(info_frame,
                                      text="\n".join([f"{column}: {value}" for column, value in right_info.items()]),
                                      anchor="nw", justify="left", font=("Helvetica", 10))
        right_column_label.pack(side="left", fill="both", expand=True)

        self.panel_panedwindow.add(panel_frame, weight=1)  # Add panel_frame with weight to allow expansion

    def close_panel(self):
        if hasattr(self, "panel_panedwindow"):
            self.panel_panedwindow.destroy()

    def test_function(self):
        filename = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if filename:
            self.clear_main_menu()  # Clear the main menu before displaying CSV data
            self.test_display_csv_data(filename)

    def predict_unchanged_labels(self):
        dtc_classifier = load(r'F:\Academic\intrusion-detection\resources\DTC_Classifier')
        selected_features = load(r'F:\Academic\intrusion-detection\resources\selected_features')
        scaler = load(r'F:\Academic\intrusion-detection\resources\std_scaler')
        onehotencoder = load(r'F:\Academic\intrusion-detection\resources\onehotencoder')

        # print(selected_features)

        # Read the dataset
        data = pd.read_csv(self.filename)  # Use raw string literal to avoid SyntaxWarning

        # Select only the columns that match the cleaned selected features
        filtered_data = data[selected_features]

        # Trim the scaler mean and scale vectors to match the number of features in the current dataset
        scaler.mean_ = scaler.mean_[:filtered_data.shape[1]]
        scaler.scale_ = scaler.scale_[:filtered_data.shape[1]]

        # Transform the data
        sc_train = scaler.transform(filtered_data.select_dtypes(include=['float64', 'int64']))

        # ----------------------------------- predict -------------------------------

        # Predict using the Decision Tree classifier
        pred_dt = dtc_classifier.predict(sc_train)

        # Add the predicted data as a new column
        filtered_data['Model Prediction'] = pred_dt

        # Reorder columns with "Model Prediction" as the first column
        cols = filtered_data.columns.tolist()
        cols = ['Model Prediction'] + [col for col in cols if col != 'Model Prediction']
        filtered_data = filtered_data[cols]

        return filtered_data

    def test_display_csv_data(self, filename=None):
        if filename:
            self.filename = filename

        if not self.filename:
            return

        if self.tree:
            self.tree.destroy()

        if self.scrollbar:
            self.scrollbar.destroy()

        # Clear existing data
        self.data = None

        self.data = self.predict_unchanged_labels()
        self.columns = self.data.columns.tolist()

        self.table_label = tk.Label(self, text="Displaying CSV Data", font=("Segoe UI Bold", 16, "bold"))
        self.table_label.pack(pady=10)

        self.back_button = tk.Button(self, text="Back", font=("Segoe UI", 12, "bold"), bg="#d9d9d9",
                                     fg="black", bd=2, cursor="hand2", relief="raised", command=self.back_to_main_menu)
        self.back_button.pack(side="top", anchor="nw", padx=3, pady=3)

        self.tree_frame = tk.Frame(self)
        self.tree_frame.pack(fill="both", expand=True)

        self.yscroll = tk.Scrollbar(self.tree_frame, orient="vertical")
        self.yscroll.pack(side="right", fill="y")

        self.xscroll = tk.Scrollbar(self.tree_frame, orient="horizontal")
        self.xscroll.pack(side="bottom", fill="x")

        self.tree = ttk.Treeview(self.tree_frame, columns=self.columns, show="headings",
                                 yscrollcommand=self.yscroll.set, xscrollcommand=self.xscroll.set)
        self.tree.pack(side="left", fill="both", expand=True)

        self.yscroll.config(command=self.tree.yview)
        self.xscroll.config(command=self.tree.xview)

        # Set style to change heading background color
        style = ttk.Style()
        style.map("Treeview.Heading", background=[("active", "lightblue")])

        for col in self.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")

        for index, row in self.data.iterrows():
            prediction = row["Model Prediction"]
            if prediction != 0:
                self.tree.insert("", "end", values=row.tolist(), tags=("red_row",))
            else:
                self.tree.insert("", "end", values=row.tolist())

        self.tree.tag_configure("red_row", background="light coral")

        self.tree.bind("<ButtonRelease-1>", self.on_click)

        # Scroll to the bottom of the frame and select the last row
        self.tree.yview_moveto(1)
        self.tree.selection_set(self.tree.get_children()[-1])


if __name__ == "__main__":
    app = IntrusionDetectionApp()
    app.mainloop()
