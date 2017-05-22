//
//  main.c
//  encrypter
//
//  Created by Dmitry Nikonenko on 4/22/17.
//  Copyright © 2017 Dmitry Nikonenko. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <gmp.h>
#include <ncurses.h>			/* ncurses.h includes stdio.h */

WINDOW *draw_generic_window(int height, int width, int starty, int startx, char *title, char *contents);
void initial_screen();
void show_about_window();
void show_input_window();
void encrypt_input(char* input_content);
void decrypt_input(char* input_content);
void write_to_file(char* data);
void show_info_window(char* info_win_content);
void destroy_win(WINDOW *win);
int get_input_file_content();
bool isprime(int x);
int generate_prime_number();
int get_random_int(int min, int max);
int get_random_from_range(int max);
int find_primitive_root(int p);
int is_primitive (int q, int a);
char decrypt(long long c1, long long c2, int x, int p);

typedef struct {
    int p;	    /* prime */
    int g;	    /* group generator */
    int y;	    /* g^x mod p */
    int x;	    /* secret exponent */
} ELG_key;

char *title_win_content = "This program encrypts data with the ElGamal assymetric key encryption algorythm. Thank you for using it!";
char *info_win_content = "g: generate new keys\te: encrypt and write to file\tr: read input.txt\ni: input the keys\td: decrypt and write to file\tq: quit program\na: about the program";
char *input_content;
char *output_win_content;

char *input_content = NULL;
char *output_file_content = NULL;

ELG_key elgamal_key;

bool keys_generated = false;

int main() {
    int ch;

    initscr();
    noecho();
    curs_set(0);
    refresh();
    initial_screen();
    
    while((ch = getch()) != 'q') {
        switch(ch) {
            case 'a':
                show_about_window();
                break;
            case 'r':
                get_input_file_content();
                initial_screen();
                break;
            case 'i':
                show_input_window();
                keys_generated = true;
                break;
            case 'e':
                encrypt_input(input_content);
                initial_screen();
                break;
            case 'd':
                decrypt_input(input_content);
                initial_screen();
                break;
            case 'w':
                write_to_file(output_win_content);
                initial_screen();
                break;
            case 'g':
                elgamal_key.p = generate_prime_number();
                elgamal_key.g = find_primitive_root(elgamal_key.p);
                elgamal_key.x = get_random_int(1, elgamal_key.p-1);

                //elgamal_key.y = fmodl(powl(elgamal_key.g, elgamal_key.x), elgamal_key.p);
                // equivalent y calculation with GNU multiple precision arithmetic library goes below:
                
                // y key calculation:
                mpz_t mpzy, mpzp, powgx;
                mpz_init(mpzy);
                mpz_init(powgx);
                mpz_init(mpzp);
                
                mpz_set_ui(mpzy, 0);
                mpz_set_ui(mpzp, elgamal_key.p);
                
                mpz_set_ui(powgx, 0);
                
                mpz_ui_pow_ui(powgx, elgamal_key.g, elgamal_key.x);
                mpz_powm_ui(mpzy, powgx, 1, mpzp);
                
                elgamal_key.y = mpz_get_d(mpzy);
                
                keys_generated = true;
                initial_screen();
                break;
        }
    }
    endwin();
    return 0;
}

void initial_screen() {
    WINDOW *status_win, *info_win, *title_win, *main_win, *output_win;
    int sw_height, sw_width, sw_starty, sw_startx;
    int iw_height, iw_width, iw_starty, iw_startx;
    int tw_height, tw_width, tw_starty, tw_startx;
    int mw_height, mw_width, mw_starty, mw_startx;
    int ow_height, ow_width, ow_starty, ow_startx;
    
    // title window params
    tw_height = 4;
    tw_width = COLS;
    tw_starty = 0;
    tw_startx = 0;
    // info window params
    iw_height = 5;
    iw_width = COLS;
    iw_starty = LINES-iw_height;
    iw_startx = 0;
    // status_window params
    sw_height = LINES-iw_height-tw_height;
    sw_width = COLS-4*COLS/5;
    sw_starty = tw_height;
    sw_startx = 0;
    // main window params
    mw_height = sw_height/2;
    mw_width = COLS - sw_width - 1;
    mw_starty = sw_starty;
    mw_startx = sw_width+1;
    // output window params
    ow_height = sw_height - mw_height;
    ow_width = mw_width;
    ow_starty = mw_starty + mw_height;
    ow_startx = mw_startx;
    
    char *key_status_win_template = "p equals:\n%d\ng equals:\n%d\nx equals:\n%d\ny equals:\n%d\n\npublic key:\np, g, y\nsecret key:\np, g, x";
    char *key_win_contents = malloc(strlen(key_status_win_template)+sizeof(itoa(elgamal_key.p))+sizeof(itoa(elgamal_key.g))+sizeof(itoa(elgamal_key.x))+sizeof(itoa(elgamal_key.y)));
    sprintf(key_win_contents, key_status_win_template, elgamal_key.p, elgamal_key.g, elgamal_key.x, elgamal_key.y);
    
    status_win = draw_generic_window(sw_height, sw_width, sw_starty, sw_startx, "KEY STATUS", key_win_contents);
    info_win = draw_generic_window(iw_height, iw_width, iw_starty, iw_startx, "INFO", info_win_content);
    title_win = draw_generic_window(tw_height, tw_width, tw_starty, tw_startx, "ELGAMAL ENCRYPTOR", title_win_content);
    main_win = draw_generic_window(mw_height, mw_width, mw_starty, mw_startx, "INPUT", input_content);
    output_win = draw_generic_window(ow_height, ow_width, ow_starty, ow_startx, "OUTPUT", output_file_content);
    
    free(key_win_contents);
}

WINDOW *draw_generic_window(int height, int width, int starty, int startx, char *title, char *contents) {
    WINDOW *generic_window;
    WINDOW *content_window;
    
    if (contents == NULL) {
        contents = "";
    }
    
    generic_window = newwin(height, width, starty, startx);
    content_window = derwin(generic_window, height-2, width-2, 1, 1);
    box(generic_window, 0, 0);
    
    mvwprintw(generic_window, 0, (width-(int)strlen(title))/2, title);
    mvwprintw(content_window, 0, 0, contents);
    curs_set(0);
    
    wrefresh(content_window);
    wrefresh(generic_window);
    
    return generic_window;
}

void show_about_window() {
    int aw_height, aw_width, aw_starty, aw_startx;
    WINDOW *about_win;
    int ch;
    
    char *about_win_content = "This program was written in spring 2017 with C and ncurses in xCode. Have fun and enjoy your day!\nMore about ncurses here - http://www.tldp.org/HOWTO/html_single/NCURSES-Programming-HOWTO/\n\nPress ESC to close this window";
    
    // about window params
    aw_height = LINES/4;
    aw_width = 4*COLS/5;
    aw_starty = 2*LINES/5;
    aw_startx = COLS/10;
    
    about_win = draw_generic_window(aw_height, aw_width, aw_starty, aw_startx, "ABOUT", about_win_content);
    while((ch = getch()) != 27);
    destroy_win(about_win);
    initial_screen();
}

void show_input_window() {
    int iw_height, iw_width, iw_starty, iw_startx;
    WINDOW *generic_window;
    WINDOW *content_window;
    int ch;
    char *title = "INPUT";
    
    // input window params
    iw_height = LINES/4;
    iw_width = 4*COLS/5;
    iw_starty = 2*LINES/5;
    iw_startx = COLS/10;

    generic_window = newwin(iw_height, iw_width, iw_starty, iw_startx);
    content_window = derwin(generic_window, iw_height-2, iw_width-2, 1, 1);
    box(generic_window, 0, 0);

    
    mvwprintw(generic_window, 0, (iw_width-(int)strlen(title))/2, title);

    
    wrefresh(content_window);
    wrefresh(generic_window);
    // enter p
    do {
        mvwprintw(content_window, 0, 0, "Please enter the value of p:");
        wrefresh(content_window);
        echo();
        curs_set(1);
        wmove(content_window, 1, 0);
        wscanw(content_window, "%d", &elgamal_key.p);
    } while (elgamal_key.p < 0);
    werase(content_window);
    
    // enter g
    do {
        mvwprintw(content_window, 0, 0, "Please enter the value of g:");
        wrefresh(content_window);
        echo();
        curs_set(1);
        wmove(content_window, 1, 0);
        wscanw(content_window, "%d", &elgamal_key.g);
    } while (elgamal_key.g < 0);
    werase(content_window);
    
    // enter x
    do {
        mvwprintw(content_window, 0, 0, "Please enter the value of x:");
        wrefresh(content_window);
        echo();
        curs_set(1);
        wmove(content_window, 1, 0);
        wscanw(content_window, "%d", &elgamal_key.x);
        
    } while (elgamal_key.x < 0);
    werase(content_window);
    
    // enter y
    do {
        mvwprintw(content_window, 0, 0, "Please enter the value of y:");
        wrefresh(content_window);
        echo();
        curs_set(1);
        wmove(content_window, 1, 0);
        wscanw(content_window, "%d", &elgamal_key.y);
        
    } while (elgamal_key.y < 0);
    werase(content_window);
    
    mvwprintw(content_window, 0, 0, "Key values set. Press ESC to close this dialogue.");
    wrefresh(content_window);
    
    noecho();
    curs_set(0);
    
    
    while((ch = getch()) != 27);
    destroy_win(generic_window);
    initial_screen();
}

void show_info_window(char* info_win_content) {
    int ew_height, ew_width, ew_starty, ew_startx;
    WINDOW *info_win;
    int ch;
    
    // about window params
    ew_height = LINES/4;
    ew_width = 4*COLS/5;
    ew_starty = 2*LINES/5;
    ew_startx = COLS/10;
    
    info_win = draw_generic_window(ew_height, ew_width, ew_starty, ew_startx, "ERROR", info_win_content);
    
    while((ch = getch()) != 27);
    destroy_win(info_win);
    initial_screen();
}

void destroy_win(WINDOW *win) {
    wborder(win, ' ', ' ', ' ',' ',' ',' ',' ',' ');
    werase(win);
    wrefresh(win);
    delwin(win);
}

int get_input_file_content() {
    FILE *textfile;
    
    if ((textfile = fopen("input.txt", "rb")) == NULL)
    {
        char *file_error_str = "The file input.txt should be in the same directory as the binary. You might also want to check the working directory and file permissions.\n\nPress ESC to close this window";
        show_info_window(file_error_str);
        return 1;
    }
    
    fseek(textfile, 0, SEEK_END);
    long fsize = ftell(textfile);
    fseek(textfile, 0, SEEK_SET);
    
    if (input_content) {
        free(input_content);
    }
    
    char *contents = malloc(fsize + 1);
    fread(contents, fsize, 1, textfile);
    fclose(textfile);
    
    contents[fsize] = 0;
    input_content = contents;
    
    return 0;
}

int get_output_file_content() {
    FILE *textfile;
    textfile = fopen("output.txt", "rb");
    
    fseek(textfile, 0, SEEK_END);
    long fsize = ftell(textfile);
    fseek(textfile, 0, SEEK_SET);
    
    if (output_file_content) {
        free(output_file_content);
    }
    
    char *contents = malloc(fsize + 1);
    fread(contents, fsize, 1, textfile);
    fclose(textfile);
    
    contents[fsize] = 0;
    output_file_content = contents;
    
    return 0;
}

void encrypt_input(char *input_content) {
    
    if (input_content && keys_generated) {
        
        if (output_win_content) {
            free(output_win_content);
        }
        FILE *crypted_file = fopen("output.txt", "w");

        int c1, c2;
        int i;
        mpz_t c1mpz, c2mpz, gmpz, kmpz, pmpz, ympz;
        mpz_init(c1mpz);
        mpz_init(c2mpz);
        mpz_init(gmpz);
        //mpz_init(kmpz);
        mpz_init(pmpz);
        

        int k;
        for (i=0; i<strlen(input_content); i++) {
            // encoding goes here
            
            k = get_random_int(2, 10);
            
            
            // for better crypting use random k in big range for each iteration
            // and use GNU multiple precision arithmetic library for c1 and c2 calculation (breaks encryption otherwise)
            
            // c1 calculation:
            // c1 = fmod(powl(elgamal_key.g, k), elgamal_key.p);
            // same calculation below with precision:
            mpz_set_ui(c1mpz, 0);
            mpz_set_ui(gmpz, elgamal_key.g);
            //mpz_set_ui(kmpz, k);
            mpz_set_ui(pmpz, elgamal_key.p);
            mpz_powm_ui(c1mpz, gmpz, k, pmpz);
            c1 = mpz_get_d(c1mpz);
            fprintf(crypted_file,"%d ", c1);

            // c2 calculation:
            // c2 = fmod(input_content[i]*powl(elgamal_key.y, k), elgamal_key.p);
            // same with precision for big ints:

            mpz_init(ympz);
            mpz_set_ui(c2mpz, 0);
            mpz_set_ui(ympz, elgamal_key.y);
            //mpz_set_ui(pmpz, elgamal_key.p);
            mpz_ui_pow_ui(c2mpz, elgamal_key.y, k);
            mpz_mul_ui(c2mpz, c2mpz, input_content[i]);
            mpz_powm_ui (c2mpz, c2mpz, 1, pmpz);
            c2 = mpz_get_d(c2mpz);
            fprintf(crypted_file,"%d ", c2);
            
        }
        fclose(crypted_file);
        get_output_file_content();
        
    } else {
        char *encrypt_error_str = "Encryption error! No input to encode or no keys.\nPress ESC";
        show_info_window(encrypt_error_str);
    }
}

void decrypt_input(char *input_content) {
    
    if (input_content && keys_generated) {
        // decryption goes here
        if (output_win_content) {
            free(output_win_content);
        }
        FILE *decrypted_file = fopen("output.txt", "w");
        
        // create buffer of 1000 long long to hold crypted keys from the input
        long long buffer[1000];
        
        // fill the buffer with ints (crypted keys)
        int i = 0;
        char* str = input_content;
        char* pch;
        pch = strtok (str," ,.-"); // omit separators between crypted ints
        while (pch != NULL)
        {
            buffer[i] = atoi(pch);
            i++;
            pch = strtok (NULL, " ,.-");
        }

        // copy buffer to new small array
        int m = 0;
        long long cypher_ints[i];
        for (m=0; m<i; m++) {
            cypher_ints[m] = buffer[m];
        }
        
        // write to output file
        int n;
        for (n=0; n<i; n=n+2) {
            // used this prints for debugging purposes
            //printf("(%lld,%lld)", cypher_ints[n], cypher_ints[n+1]);
            //printf("(%c)\n", decrypt(cypher_ints[n], cypher_ints[n+1], elgamal_key.x, elgamal_key.p));
            fprintf(decrypted_file,"%c", decrypt(cypher_ints[n], cypher_ints[n+1], elgamal_key.x, elgamal_key.p));
        }
        fclose(decrypted_file);
        
        // get back the input
        get_input_file_content();
        
        // get the output written to output file
        get_output_file_content();

        
    } else {
        char *decrypt_error_str = "Decryption error!";
        show_info_window(decrypt_error_str);
    }
}

char* append_char_to_string(char *string1, char letter) {
    
    size_t len = strlen(string1);
    char *string2 = malloc(len + 1 + 1 ); /* one for extra char, one for trailing zero */
    strcpy(string2, string1);
    string2[len] = letter;
    string2[len + 1] = '\0';
    
    return string2;
}

char decrypt(long long c1, long long c2, int x, int p) {

    //char result = fmodl(c2*powl(c1, p-1-x), p);
    // gmp below performs the same calculation but with precision
    
    mpz_t result, keyp;
    mpz_init(keyp);
    mpz_init(result);
    mpz_set_ui(result, 0);
    mpz_set_ui(keyp, p);
    mpz_ui_pow_ui(result, c1, (p-1-x));
    
    mpz_mul_ui(result, result, c2);
    mpz_powm_ui (result, result, 1, keyp);
    
    long r;
    r = mpz_get_d(result);
    
    return r;
}

void write_to_file(char* data) {
    if (data) {
        FILE *output_file = fopen("output.txt", "wb");
        if (output_file != NULL) {
            fputs(data, output_file);
            fclose(output_file);
        }
    } else {
        char *write_error_str = "Nothing to write!";
        show_info_window(write_error_str);
    }
}

int generate_prime_number() {
    int n;
    bool prime_found = false;
    do {
        // n should be bigger than integerfor encryption, chose minimal 30 as sufficient for ascii codes
        n = get_random_int(130, 1000);
        if (isprime(n)) {
            prime_found = true;
        }
    } while (prime_found == false);
    return n;
}

int get_random_from_range(int max) {
    int n;
    n = 1+(int)(max*rand()/RAND_MAX+1.0); // generate random number with maximum value int max
    return n;
}

bool isprime(int x)
{
    int d;
    for (d = 2; d <= sqrt(x); d++) //check all possible divisors
        if (x % d == 0)
            return false;
    return true;
}

int find_primitive_root(int p) {
    int o = 1;
    int k;
    int r;
    
    // (r=2; r<p; r++) - use this for minimal pr
    // (r=p; r>1; r--) - use this for maximal pr
    for (r=p; r>1; r--) {
        k = pow(r, o);
        k = k%p;
        while (k>1) {
            o++;
            k = k*r;
            k = k%p;
        }
        if (o ==(p-1)) {
            return r;
        }
        o = 1;
    }
    return -1;
}

int get_random_int(int min, int max) {
    return min + rand() % (max - min);
}
