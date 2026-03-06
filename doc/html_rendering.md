# Generating HTML Documentation with GNU GLOBAL (gtags / htags)

GNU GLOBAL is a source code tagging system that works the same way across diverse environments. With `gtags` and `htags`, you can generate a hyperlinked, searchable HTML rendering of your C source code, making it incredibly easy to navigate and read.

## Prerequisites
Ensure GNU GLOBAL is installed on your system:
```bash
sudo apt-get install global # On Debian/Ubuntu
sudo dnf install global     # On Fedora/RHEL
```

## Step-by-Step Generation (Example: `kernel/` directory)

To generate the HTML reference for the kernel module:

### 1. Build the Tag Database (`gtags`)
Navigate to the directory containing the source code you want to index, and run `gtags`:
```bash
cd /home/giacomo/devel/ipfire-wall/kernel
gtags
```
This generates `GTAGS`, `GRTAGS`, and `GPATH` database files in your current directory.

### 2. Generate the HTML Pages (`htags`)
Once the tag databases are built, run `htags` to generate the HTML frontend:
```bash
htags -v --suggest
```
*   `-v`: Verbose output to track progress.
*   `--suggest`: A macro flag that automatically enables the most popular, user-friendly options for `htags` (including function index, alphabetical index, and tree views).

This process will create a new directory named `HTML/` inside your `kernel/` folder containing the fully hyperlinked codebase. Simply open `HTML/index.html` in any web browser.

---

## Formatting for Printing (Colors and Backgrounds)

If you are generating these HTML files specifically to **print** them, you'll want a white background with high-contrast foreground text to ensure clarity on paper while saving ink.

### Default Behavior
By default, `htags` natively generates a **light theme** (black text on a pure white background), making it inherently printer-friendly right out of the box. 

### Customizing the CSS for Enhanced Printing
If you wish to tweak the default colors (e.g., to adjust syntax highlighting colors, reduce font sizes to fit more code per page, or hide UI elements during printing), `htags` makes this entirely customizable via CSS.

When you run `htags`, it generates a stylesheet at `HTML/style.css`.
To improve the printed output, you can append an `@media print` query to the bottom of this generated file. 

Example addition to `HTML/style.css`:
```css
/* Print-specific overrides */
@media print {
    body {
        background-color: white !important;
        color: black !important;
        font-size: 10pt; /* Smaller font saves paper */
    }
    
    /* Ensure links don't print as unreadable blue text */
    a:link { color: black !important; text-decoration: none; }
    a:visited { color: black !important; text-decoration: none; }
    
    /* Hide the navigation headers when printing */
    .header, .footer, .tree-view-pane {
        display: none !important; 
    }
}
```

### Advanced: Using a Persistent CSS Template
If you generate HTML frequently and don't want to edit `HTML/style.css` every time, you can create a custom `style.css.tmpl` file. 
Place your custom template inside your project directory, and `htags` will automatically use it as the base stylesheet for all future generations. Look at `/usr/local/share/gtags/style.css.tmpl` (or `/usr/share/gtags/style.css.tmpl` depending on your distro) for the default template reference.
