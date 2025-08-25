class A {
    int value;
    
    A(int value) {
        this.value = value;
    }
}

class B {
    String data;
    
    B(String data) {
        this.data = data;
    }
}

public class Alloc {
    public static void main(String[] args) {
        A objA1 = new A(10);
        A objA2 = new A(20);
        
        B objB1 = new B("Hello");
        B objB2 = new B("World");
        
    }
}
