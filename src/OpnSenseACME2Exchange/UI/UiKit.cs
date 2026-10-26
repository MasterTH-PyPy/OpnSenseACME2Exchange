namespace OpnSenseACME2Exchange.UI;

/// <summary>Kleine Fabrik für einheitliche Standard-Controls (graues Windows-Design der Tool-Suite).</summary>
internal static class UiKit
{
    public static readonly Font MonoFont = new("Consolas", 9F);
    public static readonly Font BoldFont = new("Segoe UI", 9F, FontStyle.Bold);

    public static Label Lbl(string text, bool bold = false) => new()
    {
        Text = text,
        AutoSize = true,
        Anchor = AnchorStyles.Left,
        Margin = new Padding(3, 6, 3, 3),
        MaximumSize = new Size(900, 0), // lange Hinweise umbrechen statt abschneiden
        Font = bold ? BoldFont : null!
    };

    public static TextBox Txt(int width = 260, bool password = false) => new()
    {
        Width = width,
        UseSystemPasswordChar = password,
        Anchor = AnchorStyles.Left,
        Margin = new Padding(3)
    };

    public static Button Btn(string text, EventHandler? click = null, int width = 0)
    {
        var b = new Button
        {
            Text = text,
            AutoSize = width == 0,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(8, 2, 8, 2),
            Margin = new Padding(3),
            UseVisualStyleBackColor = true
        };
        if (width > 0) { b.Width = width; b.Height = 28; }
        if (click != null) b.Click += click;
        return b;
    }

    public static CheckBox Chk(string text) => new()
    {
        Text = text,
        AutoSize = true,
        Margin = new Padding(3, 5, 3, 3)
    };

    public static GroupBox Grp(string text, Control content, DockStyle dock = DockStyle.Top)
    {
        bool auto = dock is DockStyle.Top or DockStyle.Bottom;
        var g = new GroupBox
        {
            Text = text,
            Dock = dock,
            Padding = new Padding(8),
            AutoSize = auto,
            AutoSizeMode = AutoSizeMode.GrowAndShrink
        };
        // Bei automatisch wachsenden Gruppen bestimmt der Inhalt die Höhe
        content.Dock = auto ? DockStyle.Top : DockStyle.Fill;
        g.Controls.Add(content);
        return g;
    }

    /// <summary>Zweispaltiges Formular (Label | Control).</summary>
    public static TableLayoutPanel Rows(params (string Label, Control Control)[] rows)
    {
        var t = new TableLayoutPanel
        {
            ColumnCount = 2,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(0)
        };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        foreach (var (label, control) in rows)
        {
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            if (label.Length > 0) t.Controls.Add(Lbl(label));
            else t.Controls.Add(new Label { AutoSize = true });
            t.Controls.Add(control);
        }
        return t;
    }

    public static FlowLayoutPanel Flow(params Control[] controls)
    {
        var f = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            WrapContents = true,
            Margin = new Padding(0),
            Padding = new Padding(0)
        };
        f.Controls.AddRange(controls);
        return f;
    }

    public static DataGridView Grid()
    {
        var g = new DataGridView
        {
            Dock = DockStyle.Fill,
            AllowUserToResizeRows = false,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = true,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            BackgroundColor = SystemColors.Window,
            BorderStyle = BorderStyle.FixedSingle,
            EditMode = DataGridViewEditMode.EditOnKeystrokeOrF2
        };
        g.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
        return g;
    }

    public static DataGridViewTextBoxColumn Col(string name, string header, float weight, bool readOnly = false) => new()
    {
        Name = name,
        HeaderText = header,
        FillWeight = weight,
        ReadOnly = readOnly,
        SortMode = DataGridViewColumnSortMode.NotSortable
    };

    public static Icon AppIcon()
    {
        var asm = typeof(UiKit).Assembly;
        using var s = asm.GetManifestResourceStream("OpnSenseACME2Exchange.app.ico");
        return s != null ? new Icon(s) : SystemIcons.Application;
    }

    public static Color OutcomeColor(Core.Engine.ServerOutcome o) => o switch
    {
        Core.Engine.ServerOutcome.Ok => Color.FromArgb(220, 245, 220),
        Core.Engine.ServerOutcome.Skipped => SystemColors.Window,
        Core.Engine.ServerOutcome.DryRun => Color.FromArgb(225, 235, 250),
        Core.Engine.ServerOutcome.Warning => Color.FromArgb(255, 243, 205),
        _ => Color.FromArgb(250, 215, 215)
    };
}
