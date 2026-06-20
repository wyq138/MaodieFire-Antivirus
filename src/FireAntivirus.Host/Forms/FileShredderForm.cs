using System;
using System.Drawing;
using System.Windows.Forms;
using System.IO;

namespace FireAntivirus.Host
{
    public class FileShredderForm : Form
    {
        private ListBox fileListBox;
        private Label statusLabel;

        public FileShredderForm()
        {
            InitializeComponents();
        }

        private void InitializeComponents()
        {
            this.Text = "文件粉碎 - 哈基咪杀毒";
            this.Size = new Size(600, 400);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Icon = SystemIcons.Shield;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 4,
                ColumnCount = 1
            };

            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));

            var titleLabel = new Label
            {
                Text = "文件粉碎",
                Font = new Font("微软雅黑", 18, FontStyle.Bold),
                ForeColor = Color.Black,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter
            };

            var descLabel = new Label
            {
                Text = "彻底删除文件，不可恢复",
                Font = new Font("微软雅黑", 12),
                ForeColor = Color.Red,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter
            };

            var titlePanel = new Panel
            {
                Dock = DockStyle.Fill
            };

            titlePanel.Controls.Add(titleLabel);
            titlePanel.Controls.Add(descLabel);
            mainLayout.Controls.Add(titlePanel, 0, 0);

            fileListBox = new ListBox
            {
                Dock = DockStyle.Fill,
                Font = new Font("微软雅黑", 10),
                BackColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle
            };

            mainLayout.Controls.Add(fileListBox, 0, 1);

            statusLabel = new Label
            {
                Text = "请添加要粉碎的文件",
                Font = new Font("微软雅黑", 9),
                ForeColor = Color.Gray,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            mainLayout.Controls.Add(statusLabel, 0, 2);

            var buttonPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 1
            };
            buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
            buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
            buttonPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.34f));

            var addButton = new Button
            {
                Text = "添加文件",
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Blue,
                ForeColor = Color.White,
                Dock = DockStyle.Fill,
                Cursor = Cursors.Hand
            };

            var shredButton = new Button
            {
                Text = "立即粉碎",
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Red,
                ForeColor = Color.White,
                Dock = DockStyle.Fill,
                Cursor = Cursors.Hand
            };

            var cancelButton = new Button
            {
                Text = "取消",
                Font = new Font("微软雅黑", 10),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Gray,
                ForeColor = Color.White,
                Dock = DockStyle.Fill,
                Cursor = Cursors.Hand
            };

            addButton.FlatAppearance.BorderSize = 0;
            shredButton.FlatAppearance.BorderSize = 0;
            cancelButton.FlatAppearance.BorderSize = 0;

            addButton.Click += AddFiles;
            shredButton.Click += ShredFiles;
            cancelButton.Click += (s, e) => this.Close();

            buttonPanel.Controls.Add(addButton, 0, 0);
            buttonPanel.Controls.Add(shredButton, 1, 0);
            buttonPanel.Controls.Add(cancelButton, 2, 0);
            mainLayout.Controls.Add(buttonPanel, 0, 3);

            this.Controls.Add(mainLayout);
        }

        private void AddFiles(object sender, EventArgs e)
        {
            using (var ofd = new OpenFileDialog { Multiselect = true, Filter = "所有文件 (*.*)|*.*" })
            {
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    foreach (var file in ofd.FileNames)
                    {
                        fileListBox.Items.Add(file);
                    }
                    statusLabel.Text = $"已添加 {fileListBox.Items.Count} 个文件";
                }
            }
        }

        private void ShredFiles(object sender, EventArgs e)
        {
            if (fileListBox.Items.Count > 0)
            {
                if (MessageBox.Show($"确定要粉碎这 {fileListBox.Items.Count} 个文件吗？此操作不可恢复！", "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
                {
                    int shreddedCount = 0;
                    int failedCount = 0;

                    foreach (var item in fileListBox.Items)
                    {
                        string filePath = item.ToString();
                        if (File.Exists(filePath))
                        {
                            try
                            {
                                // 实际的文件粉碎操作
                                ShredFile(filePath);
                                shreddedCount++;
                            }
                            catch (Exception ex)
                            {
                                failedCount++;
                                statusLabel.Text = $"粉碎失败: {Path.GetFileName(filePath)} - {ex.Message}";
                            }
                        }
                    }

                    fileListBox.Items.Clear();
                    statusLabel.Text = $"文件粉碎完成 - 成功: {shreddedCount}, 失败: {failedCount}";
                    MessageBox.Show($"文件粉碎完成\n成功: {shreddedCount} 个文件\n失败: {failedCount} 个文件", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }

        private void ShredFile(string filePath)
        {
            // 基本的文件粉碎实现
            // 1. 用随机数据覆盖文件
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                byte[] buffer = new byte[4096];
                Random random = new Random();
                long fileLength = fs.Length;
                long totalWritten = 0;

                while (totalWritten < fileLength)
                {
                    int bytesToWrite = (int)Math.Min(buffer.Length, fileLength - totalWritten);
                    random.NextBytes(buffer);
                    fs.Write(buffer, 0, bytesToWrite);
                    totalWritten += bytesToWrite;
                }

                fs.Flush(true);
            }

            // 2. 重命名文件
            string tempPath = Path.Combine(Path.GetDirectoryName(filePath), Path.GetRandomFileName());
            File.Move(filePath, tempPath);

            // 3. 删除文件
            File.Delete(tempPath);
        }
    }
}