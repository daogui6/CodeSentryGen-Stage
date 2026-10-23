import os
import subprocess
import tempfile
from docutils.core import publish_string

class RSTConverter:
    def __init__(self, rst_content):
        self.rst_content = rst_content

    def to_html(self):
        return publish_string(self.rst_content, writer_name='html5').decode('utf-8')

    def to_latex(self):
        return publish_string(self.rst_content, writer_name='latex').decode('utf-8')

    def to_pdf(self, output_path):
        latex_content = self.to_latex()
        with tempfile.TemporaryDirectory() as tmpdirname:
            tex_path = os.path.join(tmpdirname, 'document.tex')
            with open(tex_path, 'w', encoding='utf-8') as f:
                f.write(latex_content)
            
            try:
                subprocess.run(
                    ['pdflatex', '-interaction=nonstopmode', '-output-directory', tmpdirname, tex_path],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                pdf_src = os.path.join(tmpdirname, 'document.pdf')
                if os.path.exists(pdf_src):
                    with open(pdf_src, 'rb') as src, open(output_path, 'wb') as dst:
                        dst.write(src.read())
                    return True
            except FileNotFoundError:
                print("Error: pdflatex not found. Please install a TeX distribution to generate PDF.")
            except subprocess.CalledProcessError as e:
                print(f"Error during PDF compilation: {e}")
        return False

if __name__ == '__main__':
    rst_text = """
    Title
    =====

    This is a **reStructuredText** document.

    * Item 1
    * Item 2
    """
    converter = RSTConverter(rst_text)
    
    html_out = converter.to_html()
    print("HTML generated successfully.")
    
    latex_out = converter.to_latex()
    print("LaTeX generated successfully.")
