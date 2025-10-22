class A {}

class B {}

public class Move {
    public static void main(String[] args) {
        A objA = new A();
        B objB = new B();

        Object v1;
        Object v2;

        if (args.length > 0) {
            v1 = objB;
            v2 = objA;
        } else {
            v1 = objA;
            v2 = objB;
        }
        assert v1 != v2 : "v1 should not be equal to v2";
    }
}
