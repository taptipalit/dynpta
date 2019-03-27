#include <iostream>
#include <bits/stdc++.h>

class Person {
    public:
        int a;
        int b;

        virtual void func(int, int);
};

class Student : public Person {
    public:
        virtual void func(int, int);
};

void Person::func(int c, int d) {
    std::cout << "Sum: " << (a+b+c+d) << std::endl;
}

void Student::func(int c, int d) {
    std::cout << "Difference: " << (a+b-c-d) << std::endl;
}

int main(void) {
    Person* ptr = NULL;
    Student s;
    
    s.a = 100;
    s.b = 80;

    /*
    p.func(10,10);
    s.func(10,10);
    */

    ptr = &s;
    ptr->func(10,10);


    return 0;
}
