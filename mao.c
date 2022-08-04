#include <stdio.h>
#include <math.h>

void function( int* x) {
    
    *x = 1000;

}

void function2 (int alpha) {

    alpha = 7;

}

int function3 (int alpha) {

    alpha = 7;

    return ;

}

int main () {

    int *p;
    int x = 7;
    printf("cella di memoria di x: %d\n", &x);
    printf("valore x: %d\n", x);

    printf("cella puntata da p: %d\n", p);

    // print(p) ti stampa la cella puntata
    //print(*p) ti stampa il valore della cella puntata

    //facendo p= &x stiamo cambiando la cella puntata da p, e quindi il suo valore
    p = &x;
    printf("cella puntata da p: %d\n", p);

    //facendo p* = 5 stiamo cambiando il valore nella cella puntata da p
    *p = 5;

    printf("valore x: %d\n", x);

    function(&x);

    printf("valore x: %d\n", x);

    function2(x);

    printf("valore x: %d\n", x);


    x = function3(x)

    printf("valore x: %d\n", x);

    return 0;
}