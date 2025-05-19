#include <gtk/gtk.h>
#include <stdlib.h>
#include <unistd.h>

GtkWidget *text_view;
GtkTextBuffer *text_buffer;
char target_program[512];

// Function to append text to the GtkTextView
void append_text(const char *text) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(text_buffer, &end);
    gtk_text_buffer_insert(text_buffer, &end, text, -1);
}

// Called when the user selects a file
void on_file_set(GtkFileChooserButton *button, gpointer user_data) {
    const char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(button));
    strncpy(target_program, filename, sizeof(target_program));
}

// Called when "Start Tracing" is clicked
void on_start_clicked(GtkButton *button, gpointer user_data) {
    if (access(target_program, X_OK) != 0) {
        append_text("Error: Target program is not executable or not selected.\n");
        return;
    }

    append_text("Starting trace...\n");

    // Prepare the command to run your tracer program
    char command[1024];
    snprintf(command, sizeof(command), "sudo ./syscall_tracer %s", target_program);

    FILE *fp = popen(command, "r");
    if (!fp) {
        append_text("Failed to run tracer.\n");
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        append_text(line);
        while (gtk_events_pending()) gtk_main_iteration(); // Keep GUI responsive
    }

    pclose(fp);
    append_text("Tracing complete.\n");
}

// GTK activate function
static void activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window, *vbox, *file_chooser, *start_button, *scrolled_window;

    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "System Call Tracer");
    gtk_window_set_default_size(GTK_WINDOW(window), 600, 400);

    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    file_chooser = gtk_file_chooser_button_new("Select Target Program", GTK_FILE_CHOOSER_ACTION_OPEN);
    g_signal_connect(file_chooser, "file-set", G_CALLBACK(on_file_set), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), file_chooser, FALSE, FALSE, 0);

    start_button = gtk_button_new_with_label("Start Tracing");
    g_signal_connect(start_button, "clicked", G_CALLBACK(on_start_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), start_button, FALSE, FALSE, 0);

    scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 0);

    text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_WORD);
    gtk_container_add(GTK_CONTAINER(scrolled_window), text_view);

    text_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));

    gtk_widget_show_all(window);
}

// Main function
int main(int argc, char **argv) {
    GtkApplication *app;
    int status;

    app = gtk_application_new("com.example.SyscallTracer", G_APPLICATION_FLAGS_NONE);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);

    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}

