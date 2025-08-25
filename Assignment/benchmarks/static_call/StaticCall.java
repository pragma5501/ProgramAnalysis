class A {}

class B {}

public class StaticCall {
    static Object id(Object o) { return o; }
    public static void main(String[] args) {
        A objA1 = new A();        
        B objB1 = new B();
        A v1 = (A) id(objA1);
        B v2 = (B) id(objB1);
    }
}
