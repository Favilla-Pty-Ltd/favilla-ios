// Waiting.swift - what the app shows while it waits (issue #59, UX drop 1).
//
// Rulings of 20 and 22 Nov 2026: nothing waits on a still screen; when the KEY
// and the app wait on each other, both show it. On the KEY that is a turning
// ring on the running step and a bar; here it is the same ring, a card that
// names the KEY and what it shows, and a bar where there is a count.

import SwiftUI

/// The KEY's own mark for "this is happening now": a brass arc turning on a
/// grey ring. Still (an arc and a dot) when the owner has asked for less motion.
struct TurningRing: View {
    var size: CGFloat = 22
    var line: CGFloat = 2
    @Environment(\.accessibilityReduceMotion) private var still

    var body: some View {
        // The angle comes from the clock, not from an animation started on appear:
        // a repeating animation begun while the page was still being laid out took
        // the layout change with it, and the arc flew off its ring (build 250).
        TimelineView(.animation(minimumInterval: 1.0 / 30, paused: still)) { t in
            let turn = still ? 0 : t.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 0.9) / 0.9
            ZStack {
                Circle().stroke(Brand.line, lineWidth: line)
                Circle().trim(from: 0, to: 0.3)
                    .stroke(Brand.brass, style: StrokeStyle(lineWidth: line, lineCap: .round))
                    .rotationEffect(.degrees(turn * 360))
                if still { Circle().fill(Brand.brass).frame(width: size * 0.36, height: size * 0.36) }
            }
            .padding(line / 2)
            .frame(width: size, height: size)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// The app is waiting: on a press on the KEY, or on work that is under way.
/// `title` says where to look ("Check your KEY"), `detail` what is there.
struct WaitCard: View {
    let title: String
    var detail: String? = nil

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            TurningRing(size: 22).padding(.top, 1)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(Brand.font(15, .semibold)).foregroundStyle(Brand.ink).fixedSize(horizontal: false, vertical: true)
                if let detail, !detail.isEmpty {
                    Text(detail).font(Brand.small).foregroundStyle(Brand.grey).fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Brand.brass.opacity(0.5), lineWidth: 1))
        .accessibilityElement(children: .combine)
    }
}

/// A thin bar, 0 to 1, like the one on the KEY's ember page.
struct WaitBar: View {
    let fraction: Double

    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(Brand.line)
                Capsule().fill(Brand.brass).frame(width: max(4, g.size.width * min(1, max(0, fraction))))
            }
        }
        .frame(height: 4)
        .animation(.easeOut(duration: 0.25), value: fraction)
        .accessibilityLabel("\(Int((min(1, max(0, fraction)) * 100).rounded())) percent")
    }
}
