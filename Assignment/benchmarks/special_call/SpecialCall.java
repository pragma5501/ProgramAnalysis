
class A {
    Object fld;
    A(Object value) {
        this.fld = value;
    }    
}

class B {
    Object fld;
    B(Object value) {
        this.fld = value;
    }    
}

class C{}


public class SpecialCall {
    static Object id(Object o) { return o; }
    public static void main(String[] args) {
        C objC = new C();
        A a = new A(objC);
        B b = new B(objC);
        // assert a.fld == b.fld : "a.fld should be equal to b.fld";
    }
}
