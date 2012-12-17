# Darwin-Trace

### これはなに？
MacOS X darwinの上でバイナリファイルの関数呼び出しとリターンをフックして記録するトレーサです。

たとえば



	#include <stdio.h>

	int fibonacci(int i) {
		if (i == 0 || i == 1) {
			return 1;
		} else {
			return fibonacci(i - 1) + fibonacci(i - 2);
		}
	}

	int main(void)
	{
    	printf("%d\n", fibonacci(3));
    	return 0;
    }
    
というソースコードに対して、コンパイルしたものを指定して実行すると

	$> sudo ./tracer testcode/fibonacci
	Password:
	[Tracer] child_proc: 73550
	[Tracer] ===> [ _main (at 0x100000ec0)]
	[Tracer]     ===> [ _fibonacci (at 0x100000e60)]
	[Tracer]         ===> [ _fibonacci (at 0x100000e60)]
	[Tracer]             ===> [ _fibonacci (at 0x100000e60)]
	[Tracer]             <=== [ _fibonacci (at 0x100000ebb)]
	[Tracer]             ===> [ _fibonacci (at 0x100000e60)]
	[Tracer]             <=== [ _fibonacci (at 0x100000ebb)]
	[Tracer]         <=== [ _fibonacci (at 0x100000ebb)]
	[Tracer]         ===> [ _fibonacci (at 0x100000e60)]
	[Tracer]         <=== [ _fibonacci (at 0x100000ebb)]
	[Tracer]     <=== [ _fibonacci (at 0x100000ebb)]
	3
	[Tracer] <=== [ _main (at 0x100000efd)]
	[Tracer]  Process :73550 Terminated
	
という出力が得られます。

### なぜこれをつくったか？
普段MacOSXの上で開発しているのですが、他の人の書かれたコードを読むとき、関数呼び出しがどういう流れで行われているかが分からない状態だと、ソースコードをひたすらgrepして上下に移動することになります。かといって毎回デバッガを起動して全部の関数にブレークポイントを貼って、トラップしては進めて、としてメモって行くのもめんどくさいので、それの指針になるものが欲しいということで作成しました。

また、Linuxだとtracef（hogetrace?）というツールを書かれた方がいらっしゃるのですが、それをMacにかなりの劣化版として移植したものがこのツールです。

とりあえずはそれにならって、デバッグ情報をわざわざつけてビルドしなくても、シンボルのストリップさえ受けていなければ、関数のトレースがようにしています。

仕組みとしては、まずバイナリを読み込んで、シンボルテーブルを探し、各関数の先頭アドレスを取得してそのアドレスに対してブレークポイントを貼っています。一方でMacOSXの10.5以降ではバイナリの各セクションをロード時にランダムなアドレス空間にロードし、他セクションを指定するアドレスに関してはリロケーションすることによって、メモリ上にバイナリを展開して実行するようになっています。したがって、アタッチする側からも各関数の実行時における実際のアドレスはわからないので、それらを無効化して実行する処理もしています。

各関数の先頭アドレスを取得したら、今度はテキストセクションの各関数を逆アセンブルしてret命令にもブレークポイントを指定しています。
以上のブレークポイントの注入処理がすべて完了したら実際にプログラムをローンチし、ブレークポイントでトラップするたびにトラップ時のプログラムカウンタの値からどの関数のエントリ／リターンかを判断し、記録しています。

### Build
* requirements
	* udis86 (Intel命令セットの逆アセンブルライブラリ)
	* MacOS X(っていうかMach-oフォーマットのOS /usr/include/mach-oのディレクトリがないとだめ。Linuxではバイナリフォーマットとかなにから何まで違うので無理です)

* build

		make
	
	をたたくだけです。成功すればtracerというバイナリファイルが出力されるはず。
### execution
* Mac OS X は他のプロセスに対してポートを開くときにそのプロセスの実行ファイルが署名されている必要があります(Max OS X Lion以降でgdbを起動させたときにパスワードを求められるのはそのため)。このプログラムは署名をつけたりなどはしていないので、sudoによって管理者特権で実行しないと走りません。

		sudo ./tracer XXX(target_process)

	
### この先やること
* C++シンボルのデマングル。今のところこのソースコードはすべてCで書いているのでデマングル用のフィルタも、自分でCでかきたい。
* プロセスのforkとかpthreadへの対応。今はシングルプロセス／シングルスレッドのみ
* ライブラリ関数の呼び出し（stubセクションのjmp命令をフックするのが一番現実的。Linuxでいうpltの呼び出し）をフックする。
* 時間計測？っつかプロファイラーっぽくする。このトレーサを先に見てもらった人のうちの100％（２人中２人w）に言われた。
* 内部のデータ管理構造をもう少し早いものにする。とりあえずはハッシュテーブルの実装で行くか。
