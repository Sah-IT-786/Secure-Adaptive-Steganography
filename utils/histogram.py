import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
import cv2
from tkinter import filedialog, Tk, Button, Label, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Function to calculate the histogram of an image
def calculate_histogram(image):
    # Convert image to grayscale for simplicity, to get luminance (brightness) information
    gray_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2GRAY)
    
    # Calculate the histogram
    hist, bins = np.histogram(gray_image.flatten(), bins=256, range=[0, 256])
    
    # Normalize the histogram (for better visualization)
    hist = hist / hist.sum()
    
    return hist, bins

# Function to plot a histogram
def plot_histogram(ax, hist, bins, title, color='black'):
    ax.plot(bins[:-1], hist, color=color, lw=2)
    ax.set_title(title)
    ax.set_xlabel("Pixel Intensity")
    ax.set_ylabel("Normalized Frequency")
    ax.grid(True)

# Function to compare histograms of two images
def compare_histograms(hist1, hist2):
    # Calculate the difference between the two histograms using a simple L1 distance (sum of absolute differences)
    diff = np.sum(np.abs(hist1 - hist2))
    
    return diff

# Function to load and compare images
def compare_images():
    # Open file dialogs to load the original and stego images
    original_image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    stego_image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    
    if not original_image_path or not stego_image_path:
        messagebox.showerror("Error", "Please select both images!")
        return
    
    # Load the images
    original_image = Image.open(original_image_path)
    stego_image = Image.open(stego_image_path)
    
    # Calculate histograms
    hist_original, bins_original = calculate_histogram(original_image)
    hist_stego, bins_stego = calculate_histogram(stego_image)
    
    # Create a matplotlib figure for the comparison
    fig, ax = plt.subplots(1, 2, figsize=(12, 6))

    # Plot histograms
    plot_histogram(ax[0], hist_original, bins_original, "Original Image Histogram", color='blue')
    plot_histogram(ax[1], hist_stego, bins_stego, "Stego Image Histogram", color='red')

    # Calculate the difference in histograms
    diff = compare_histograms(hist_original, hist_stego)
    
    # Display the difference between the histograms
    ax[1].plot([0, 255], [1, 1], 'k--', label=f"Difference: {diff:.6f}")  # Example line to show diff
    ax[1].legend()

    plt.tight_layout()

    # Show the plot in a Tkinter window
    canvas = FigureCanvasTkAgg(fig, master=root)  
    canvas.draw()
    canvas.get_tk_widget().pack(pady=20)

    # Display the histogram difference in a message box
    messagebox.showinfo("Histogram Comparison", f"Histogram Difference: {diff:.6f}")
    print(f"Histogram Difference: {diff:.6f}")

# GUI Application Class
class HistogramComparisonApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Histogram Comparison")
        self.root.geometry("800x600")

        # UI Layout
        Label(root, text="Compare Histograms of Images", font=("Helvetica", 18)).pack(pady=10)

        Button(root, text="Compare Images", command=compare_images).pack(pady=20)

# Main Program
if __name__ == "__main__":
    root = Tk()
    app = HistogramComparisonApp(root)
    root.mainloop()
