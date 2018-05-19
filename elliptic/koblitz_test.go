package elliptic_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/sammy00/crypto/elliptic"
)

func TestKoblitzBasePoint(t *testing.T) {
	koblitzBTC := btcec.S256()

	koblitzLocal := elliptic.P256k1().Params()

	if 0 != koblitzBTC.Gx.Cmp(koblitzLocal.Gx) {
		t.Fatalf("invalid Gx: got %s, want %s", koblitzLocal.Gx.String(), koblitzBTC.Gx.String())
	}

	if 0 != koblitzBTC.Gy.Cmp(koblitzLocal.Gy) {
		t.Fatalf("invalid Gx: got %s, want %s", koblitzLocal.Gy.String(), koblitzBTC.Gy.String())
	}
}

func TestKoblitzMarshaling(t *testing.T) {
	curve := elliptic.P256k1()

	t.Run("Valid Point", func(t *testing.T) {
		Gx, Gy := curve.Params().Gx, curve.Params().Gy

		data := elliptic.Marshal(curve, Gx, Gy)
		GxRec, GyRec := elliptic.Unmarshal(curve, data)
		if (nil == GxRec) || (nil == GyRec) {
			t.Fatal("both of x and y shouldn't be nil")
		}
	})

	t.Run("Invalid Point", func(t *testing.T) {
		// a point not on curve
		x, y := new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)

		data := elliptic.Marshal(curve, x, y)
		xRec, yRec := elliptic.Unmarshal(curve, data)
		if (nil != xRec) || (nil != yRec) {
			t.Fatal("both of x and y should be nil")
		}
	})
}

func TestKoblitzOffCurve(t *testing.T) {
	curve := elliptic.P256k1()
	params := curve.Params()

	GxBad, _ := new(big.Int).SetString(params.Gx.String(), 10)
	GxBad.Sub(GxBad, new(big.Int).SetInt64(1))

	if curve.IsOnCurve(GxBad, params.Gy) {
		t.Fatal("This point shouldn't be on curve")
	}

	GyBad, _ := new(big.Int).SetString(params.Gy.String(), 10)
	GyBad.Sub(GyBad, new(big.Int).SetInt64(1))

	if curve.IsOnCurve(params.Gx, GyBad) {
		t.Fatal("This point shouldn't be on curve")
	}
}
func TestKoblitzOnCurve(t *testing.T) {
	curve := elliptic.P256k1()

	params := curve.Params()

	if !curve.IsOnCurve(params.Gx, params.Gy) {
		t.Fatal("Base point should be on curve")
	}
}

type baseMultTest struct {
	k    string
	x, y string
}

var secp256k1BaseMultTestVec = []baseMultTest{
	{
		"AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522",
		"34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6",
		"B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232",
	},
	{
		"7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3",
		"D74BF844B0862475103D96A611CF2D898447E288D34B360BC885CB8CE7C00575",
		"131C670D414C4546B88AC3FF664611B1C38CEB1C21D76369D7A7A0969D61D97D",
	},
	{
		"6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D",
		"E8AECC370AEDD953483719A116711963CE201AC3EB21D3F3257BB48668C6A72F",
		"C25CAF2F0EBA1DDB2F0F3F47866299EF907867B7D27E95B3873BF98397B24EE1",
	},
	{
		"376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC",
		"14890E61FCD4B0BD92E5B36C81372CA6FED471EF3AA60A3E415EE4FE987DABA1",
		"297B858D9F752AB42D3BCA67EE0EB6DCD1C2B7B0DBE23397E66ADC272263F982",
	},
	{
		"1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9",
		"F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3",
		"F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE",
	},
}

func TestKoblitzScalarBaseMult(t *testing.T) {
	curve := elliptic.P256k1()

	for i, v := range secp256k1BaseMultTestVec {
		k, ok := new(big.Int).SetString(v.k, 16)
		if !ok {
			t.Errorf("#%d: bad value for k: %s\n", i, v.k)
			continue
		}

		x, y := curve.ScalarBaseMult(k.Bytes())
		if (fmt.Sprintf("%X", x) != v.x) || (fmt.Sprintf("%X", y) != v.y) {
			t.Errorf("#%d: bad output for k=%s: got (%X, %X), want (%s, %s)", i, v.k, x, y, v.x, v.y)
		}
	}
}
